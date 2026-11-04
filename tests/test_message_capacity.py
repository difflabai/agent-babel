"""Retained history must not block at the old bound or lose retry protection."""
import tempfile
from pathlib import Path
import unittest

from babel.core import BridgeError, MAX_RETAINED_MESSAGES, Store


class MessageCapacityTests(unittest.TestCase):
    def test_old_limit_and_exact_new_limit_preserve_history_across_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'bridge.sqlite3'
            store = Store(path)
            # Pending historical rows are outside rolling rate windows but remain active.
            # Completed inactive threads are covered by test_retirement.
            def fill(first, last):
                store.db.executemany('''INSERT INTO messages
                    (id,source,recipient,text,root_id,hops,status,provenance,created)
                    VALUES(?,'ada','grokbot','retained history',?,1,?,'manual',1)''',
                    ((f'history-{i:06d}', f'history-{i:06d}',
                      'queued') for i in range(first, last)))
                store.db.commit()

            fill(0, 10000)
            self.assertGreater(MAX_RETAINED_MESSAGES, 10000)
            accepted = store.stage('ada', 'grokbot', 'capacity canary',
                                   message_id='capacity-canary-0001')
            self.assertFalse(accepted['duplicate'])
            fill(10000, MAX_RETAINED_MESSAGES - 1)
            store.close()
            store = Store(path)
            try:
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM messages').fetchone()[0],
                                 MAX_RETAINED_MESSAGES)
                self.assertTrue(store.stage('ada', 'grokbot', 'capacity canary',
                    message_id='capacity-canary-0001')['duplicate'])
                with self.assertRaises(BridgeError) as changed:
                    store.stage('ada', 'grokbot', 'changed content', message_id='capacity-canary-0001')
                self.assertEqual(changed.exception.status, 409)
                with self.assertRaises(BridgeError) as full:
                    store.stage('ada', 'grokbot', 'new message', message_id='capacity-overflow-001')
                self.assertEqual(full.exception.status, 507)
                # Existing receipt operations remain possible when capacity is full.
                store.acknowledge('history-000001', 'grokbot')
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM messages').fetchone()[0],
                                 MAX_RETAINED_MESSAGES)
                self.assertEqual(store.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            finally:
                store.close()


if __name__ == '__main__':
    unittest.main()
