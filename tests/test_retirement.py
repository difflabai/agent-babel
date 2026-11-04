import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from babel.core import BridgeError, ROOT, Store, THREAD_IDLE_SECONDS


NOW = 2000000000
OLD = NOW - THREAD_IDLE_SECONDS - 1


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')

    def tearDown(self):
        self.store.close()

    def message(self, mid, status='acknowledged', at=OLD, parent=None):
        data = dict(source='ada', recipient='grokbot', text='retirement test', message_id=mid)
        if parent:
            data.update(source=parent['recipient'], recipient=parent['source'], reply_to=parent['id'])
        with patch('babel.core.time.time', return_value=at):
            row = self.store.stage(**data)['message']
            if status != 'draft':
                self.store.approve(row['id'])
            if status == 'acknowledged':
                self.store.acknowledge(row['id'], row['recipient'])
            if status == 'canceled':
                self.store.cancel(row['id'])
        return self.store._row(mid)

    def sweep(self, dry_run=False):
        with patch('babel.core.time.time', return_value=NOW):
            return self.store.retire_threads(dry_run=dry_run)

    def test_whole_thread_boundary_and_history_preserved(self):
        first = self.message('finished-root-001')
        child = self.message('finished-child-001', parent=first)
        self.message('boundary-root-001', at=NOW - THREAD_IDLE_SECONDS)
        active = self.message('recent-child-root')
        self.message('recent-child-001', parent=active, at=NOW - 1)
        before = self.store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        preview = self.sweep(dry_run=True)
        self.assertEqual(preview['eligible_threads'], 2)
        self.assertEqual(preview['eligible_messages'], 3)
        self.assertEqual(preview['retired_messages'], 0)
        result = self.sweep()
        self.assertEqual((result['active_messages'], result['retired_messages']), (2, 3))
        self.assertEqual(self.store._row(child['id'])['retired_at'], NOW)
        self.assertEqual(len(self.store.history()), 5)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0], before)
        self.assertEqual(self.sweep()['eligible_messages'], 0)

    def test_pending_messages_and_recent_receipts_or_cancels_protect_thread(self):
        for status in ('draft', 'queued'):
            first = self.message('pending-root-' + status)
            self.message('pending-child-' + status, status=status, parent=first)
        recent = self.message('recent-receipt-01', status='queued')
        canceled = self.message('recent-canceled01', status='draft')
        with patch('babel.core.time.time', return_value=NOW):
            self.store.acknowledge(recent['id'], recent['recipient'])
            self.store.cancel(canceled['id'])
        self.assertEqual(self.sweep()['eligible_messages'], 0)

    def test_polls_and_non_activity_events_do_not_extend_lifetime(self):
        row = self.message('quiet-history-001')
        with patch('babel.core.time.time', return_value=NOW):
            self.store.history(role='ada')
            self.store.message_status(row['id'], 'ada')
            self.store.claim_message(row['id'], 'grokbot', 'polling-claim-001')
            self.store.db.execute("INSERT INTO events(message_id,action,actor,created) VALUES(?,'manual-export-prepared','local-operator',?)", (row['id'], NOW))
            self.store.db.commit()
        self.assertEqual(self.sweep()['eligible_messages'], 1)

    def test_archived_retry_receipt_and_new_reply_behavior(self):
        row = self.message('retry-history-001', status='queued')
        with patch('babel.core.time.time', return_value=OLD):
            self.store.claim_message(row['id'], 'grokbot', 'original-claim-001')
            self.store.acknowledge_claim(row['id'], 'grokbot', 'original-claim-001')
        self.sweep()
        retry = self.store.stage('ada', 'grokbot', 'retirement test', message_id=row['id'])
        self.assertTrue(retry['duplicate'])
        self.assertEqual(retry['message']['retired_at'], NOW)
        self.assertEqual(self.store.acknowledge_claim(row['id'], 'grokbot', 'original-claim-001')['status'], 'acknowledged')
        with self.assertRaises(BridgeError) as changed:
            self.store.stage('ada', 'grokbot', 'changed text', message_id=row['id'])
        self.assertEqual(changed.exception.status, 409)
        with self.assertRaises(BridgeError) as retired:
            self.store.stage('grokbot', 'ada', 'new reply', reply_to=row['id'])
        self.assertEqual(retired.exception.status, 410)
        self.assertFalse(self.store.stage('grokbot', 'ada', 'new thread')['duplicate'])
        self.assertEqual(self.store.inbox('grokbot'), [])

    def test_admission_reclaims_finished_threads_when_sweep_was_missed(self):
        self.message('capacity-finished')
        self.message('capacity-pending1', status='queued')
        with patch('babel.core.MAX_RETAINED_MESSAGES', 2), patch('babel.core.time.time', return_value=NOW):
            self.store.stage('ada', 'grokbot', 'accepted', message_id='capacity-accepted')
            with self.assertRaises(BridgeError) as full:
                self.store.stage('ada', 'grokbot', 'blocked', message_id='capacity-blocked0')
        self.assertEqual(full.exception.status, 507)
        self.assertEqual(self.store.retirement_usage(), {'active_messages': 2, 'retired_messages': 1, 'total_messages': 3})

    def test_sweep_and_reply_serialize_on_two_connections(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bridge.sqlite3'
            first, second = Store(path), Store(path)
            try:
                with patch('babel.core.time.time', return_value=OLD):
                    row = first.stage('ada', 'grokbot', 'old', message_id='race-thread-0001')['message']
                    first.approve(row['id']); first.acknowledge(row['id'], 'grokbot')
                with patch('babel.core.time.time', return_value=NOW):
                    # A reply committed before a sweep protects its whole thread.
                    second.stage('grokbot', 'ada', 'new', message_id='race-reply-00001', reply_to=row['id'])
                    self.assertEqual(first.retire_threads()['eligible_messages'], 0)
                    second.cancel('race-reply-00001')
                with patch('babel.core.time.time', return_value=NOW + THREAD_IDLE_SECONDS + 1):
                    self.assertEqual(first.retire_threads()['eligible_messages'], 2)
                with self.assertRaises(BridgeError) as closed:
                    second.stage('grokbot', 'ada', 'late', reply_to=row['id'])
                self.assertEqual(closed.exception.status, 410)
                self.assertEqual(second.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            finally:
                first.close(); second.close()

    def test_failed_sweep_rolls_back_and_restart_backup_keep_retirement(self):
        self.message('rollback-root-001')
        self.message('rollback-root-002')
        self.store.db.execute("CREATE TRIGGER reject_retirement BEFORE UPDATE OF retired_at ON messages WHEN NEW.id='rollback-root-002' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
        self.store.db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            self.sweep()
        self.assertEqual(self.store.retirement_usage()['retired_messages'], 0)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bridge.sqlite3'
            self.store.db.execute('DROP TRIGGER reject_retirement'); self.store.db.commit()
            with sqlite3.connect(path) as dest:
                self.store.db.backup(dest)
            persistent = Store(path)
            with patch('babel.core.time.time', return_value=NOW):
                persistent.retire_threads()
            backup = persistent.backup(); persistent.close()
            for dbpath in (path, path.parent / 'backups' / backup):
                restored = Store(dbpath)
                try:
                    self.assertEqual(restored.retirement_usage()['retired_messages'], 2)
                    self.assertEqual(restored.db.execute('PRAGMA user_version').fetchone()[0], 4)
                finally:
                    restored.close()

    def test_cli_preview_apply_and_repeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / 'bridge.sqlite3')
            with patch('babel.core.time.time', return_value=1):
                store.stage('ada', 'grokbot', 'historical', message_id='cli-history-0001')
                store.approve('cli-history-0001')
                store.acknowledge('cli-history-0001', 'grokbot')
            store.close()
            for options, retired, eligible in ((['--dry-run'], 0, 1), ([], 1, 1), (['--dry-run'], 1, 0)):
                result = subprocess.run([sys.executable, '-m', 'babel', 'retire', *options],
                    cwd=ROOT, env={**os.environ, 'BABEL_DATA_DIR': tmp},
                    capture_output=True, text=True, check=True, timeout=15)
                data = json.loads(result.stdout)
                self.assertEqual(data['retired_messages'], retired)
                self.assertEqual(data['eligible_messages'], eligible)


if __name__ == '__main__':
    unittest.main()
