"""Account receiver tests use synthetic mailboxes/native peers, never models."""
from concurrent.futures import Future
import contextlib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from babel import account_wake as wake
from babel import native_receiver as native
from tests.account_client_fixture import DispatcherTests, SID, TURN

SID2 = '20000000-0000-4000-8000-000000000002'
EMBER = 'bits255.dots.ada_20261002'


class AccountWakeTests(DispatcherTests, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.hook()
        self.config = self.helper.root.parent
        self.config.chmod(0o700)
        self.account_file = self.config / 'trusted-account.json'
        wake.write_json(self.account_file, {'schema_version': 1, 'peer': self.helper.peer})
        self.box = wake.Mailbox(self.config, self.helper, SID)
        self.native = Mock()
        self.native.metadata.return_value = {'id': SID, 'cwd': '/synthetic/task', 'status': 'idle'}
        self.route = {'recipient': EMBER, 'conversation_id': 'synthetic-conversation'}
        self.rows = [{'id': 'synthetic-wake-message', 'seq': 1, 'source': EMBER,
                      'recipient': self.box.participant, 'conversation_id': self.route['conversation_id'],
                      'text': 'Synthetic task content must not enter the native notification.',
                      'status': 'queued', 'created': 10, 'approved': 10}]
        self.busy = self.acked = False
        self.helper.call = Mock(side_effect=self.remote)

    def remote(self, path, name, args, **kwargs):
        self.assertEqual(kwargs['credential'], self.box.path / 'token')
        self.assertEqual(kwargs['expected_digest'], self.box.digest)
        if name == 'list_contacts':
            return {'contacts': [self.route]}
        if name == 'receive_messages':
            return {'messages': [row for row in self.rows if row['seq'] > args['after']][:50]}
        if name == 'claim_message':
            return {'claimed': not self.busy, 'claim_id': args['claim_id'],
                    'message': self.rows[0], 'expires': time.time() + 120}
        if name == 'message_status':
            return {'message': dict(self.rows[0], status='acknowledged' if self.acked else 'queued')}
        raise AssertionError(name)

    def delivery(self):
        return wake.Delivery(self.box, self.native)

    def test_unenrolled_loaded_thread_never_creates_identity_or_registration(self):
        before = set(self.helper.root.iterdir())
        with self.assertRaises(wake.Deferred):
            wake.Mailbox(self.config, self.helper, SID2)
        self.assertEqual(set(self.helper.root.iterdir()), before)
        self.assertFalse(list(self.config.rglob('*registration*')))
        self.helper.call.assert_not_called()

    def test_duplicate_and_restart_only_queue_once_with_reserved_claim_and_no_peer_text(self):
        delivery = self.delivery()
        self.assertEqual(delivery.step(), 1)
        self.assertEqual(delivery.step(), 0)
        self.assertEqual(self.delivery().step(), 0)
        self.assertEqual(self.native.queue.call_count, 1)
        args = self.native.queue.call_args.args
        self.assertEqual(args[0], SID)
        self.assertIn('Reserved claim ID: wake_', args[2])
        self.assertIn('--native-session ' + SID, args[2])
        self.assertNotIn(self.rows[0]['text'], args[2])
        self.assertNotIn('acknowledge_message', [call.args[1] for call in self.helper.call.call_args_list])

    def test_empty_inbox_and_claim_ack_races_do_not_queue(self):
        rows, self.rows = self.rows, []
        self.assertEqual(self.delivery().step(), 0)
        self.rows = rows
        self.busy = True
        self.assertEqual(self.delivery().step(), 0)
        self.busy, self.acked = False, True
        self.assertEqual(self.delivery().step(), 0)
        self.native.queue.assert_not_called()

    def test_uncertain_queue_retains_intent_and_quarantines_restart(self):
        self.native.queue.side_effect = TimeoutError
        with self.assertRaises(TimeoutError):
            self.delivery().step()
        with self.assertRaises(wake.Quarantined):
            self.delivery()
        state = wake.read_json(self.box.path / 'account-wake-state.json')
        self.assertEqual(state['submissions'][self.rows[0]['id']]['state'], 'submitting')
        self.assertEqual(self.native.queue.call_count, 1)

    def test_uncertain_claim_is_not_retried(self):
        remote = self.remote
        def fail(path, name, args, **kwargs):
            if name == 'claim_message':
                raise TimeoutError
            return remote(path, name, args, **kwargs)
        self.helper.call.side_effect = fail
        with self.assertRaises(TimeoutError):
            self.delivery().step()
        with self.assertRaises(wake.Quarantined):
            self.delivery()
        self.native.queue.assert_not_called()

    def test_lost_post_submit_commit_is_quarantined(self):
        write, calls = wake.write_json, []
        def fail(path, value):
            calls.append(1)
            if len(calls) == 3:
                raise OSError('Synthetic fsync failure after queue acceptance')
            write(path, value)
        with patch.object(wake, 'write_json', side_effect=fail):
            with self.assertRaises(OSError):
                self.delivery().step()
        self.assertEqual(self.native.queue.call_count, 1)
        with self.assertRaises(wake.Quarantined):
            self.delivery()

    def test_failed_intent_write_never_claims_or_queues(self):
        with patch.object(wake, 'write_json', side_effect=OSError):
            with self.assertRaises(OSError):
                self.delivery().step()
        self.assertNotIn('claim_message', [call.args[1] for call in self.helper.call.call_args_list])
        self.native.queue.assert_not_called()

    def test_pending_rotation_waits_without_committing_candidate_or_network(self):
        pending = self.box.path / 'resume-token'
        pending.write_text('synthetic-pending-candidate')
        pending.chmod(0o600)
        before = (self.box.path / 'token').read_bytes()
        with self.assertRaises(wake.Deferred):
            wake.Mailbox(self.config, self.helper, SID)
        self.assertEqual((self.box.path / 'token').read_bytes(), before)
        self.assertTrue(pending.exists())
        self.helper.call.assert_not_called()

    def test_cross_session_manifest_and_recipient_are_rejected(self):
        request = self.box.path / 'trusted-enrollment.json'
        data = wake.read_json(request)
        data['native_id'] = SID2
        wake.write_json(request, data)
        with self.assertRaises(ValueError):
            wake.Mailbox(self.config, self.helper, SID)
        self.rows[0]['recipient'] = 'different-mailbox'
        with self.assertRaises(ValueError):
            self.delivery().step()
        self.native.queue.assert_not_called()

    def test_old_watcher_lock_and_uncertain_state_are_preserved(self):
        path = self.box.path / 'wake.lock'
        with wake.locked(path):
            with self.assertRaises(wake.Deferred):
                with wake.locked(path, create=False):
                    self.fail('Competing watcher acquired lock')
        path = self.box.path / 'wake-state.json'
        wake.write_json(path, {'thread': SID, 'submissions': {'old-message': {'state': 'submitting'}}})
        with self.assertRaises(wake.Quarantined):
            self.delivery()
        self.assertTrue(path.exists())
        path.unlink()
        pending = self.box.path / 'wake-state.pending.json'
        wake.write_json(pending, {})
        with self.assertRaises(wake.Quarantined):
            self.delivery()
        self.assertTrue(pending.exists())

    def test_committed_previous_watcher_submission_is_not_replayed(self):
        wake.write_json(self.box.path / 'relay-session-wake-state.json',
                        {'thread': SID, 'participant': self.box.participant,
                         'submissions': {self.rows[0]['id']: {'state': 'accepted'}}})
        self.assertEqual(self.delivery().step(), 0)
        self.native.queue.assert_not_called()

    def test_closed_thread_never_claims(self):
        self.native.metadata.side_effect = native.NativeUnavailable
        with self.assertRaises(native.NativeUnavailable):
            self.delivery().step()
        self.helper.call.assert_not_called()

    def test_nonfinite_claim_expiry_is_quarantined(self):
        remote = self.remote
        def nan(*args, **kwargs):
            result = remote(*args, **kwargs)
            if args[1] == 'claim_message':
                result['expires'] = float('nan')
            return result
        self.helper.call.side_effect = nan
        with self.assertRaises(wake.Quarantined):
            self.delivery().step()
        self.native.queue.assert_not_called()

    def test_legacy_mapping_requires_existing_exact_binding_and_does_not_create_one(self):
        legacy = self.config / 'instances/codex-reviewed'
        legacy.mkdir(mode=0o700, parents=True)
        token = 'synthetic-reviewed-credential'
        wake.write_json(legacy / 'enrollment.json', {'client': 'codex', 'participant': 'synthetic.legacy',
                                                    'sha256': hashlib.sha256(token.encode()).hexdigest()})
        (legacy / 'token').write_text(token)
        (legacy / 'token').chmod(0o600)
        wake.write_json(self.config / 'native-bindings.json',
                        {'schema_version': 1, 'bindings': {'codex:' + SID: 'reviewed'}})
        binding = legacy / 'account-native-binding.json'
        with self.assertRaises(FileNotFoundError):
            wake.Mailbox(self.config, self.helper, SID)
        self.assertFalse(binding.exists())
        wake.write_json(binding, {'peer': self.helper.peer, 'client': 'codex',
                                 'native_id': SID, 'participant': 'synthetic.legacy'})
        box = wake.Mailbox(self.config, self.helper, SID)
        self.assertEqual(box.path, legacy)
        self.assertEqual(box.participant, 'synthetic.legacy')


class ReceiverSchedulingTests(unittest.TestCase):
    def test_new_loaded_sessions_discovered_automatically_and_failures_isolated(self):
        receiver = object.__new__(wake.Receiver)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        receiver.root = Path(temporary.name)
        receiver.native = Mock()
        receiver.native.loaded.return_value = [SID]
        receiver.pool = Mock()
        receiver.workers = 2
        receiver.futures, receiver.due, receiver.statuses = {}, {}, {}
        pending = Future()
        receiver.pool.submit.side_effect = [pending, Future()]
        receiver.tick()
        self.assertEqual(receiver.pool.submit.call_args.args[1], SID)
        # One stalled session leaves a worker for a new session without a registry.
        receiver.native.loaded.return_value = [SID, SID2]
        receiver.tick()
        self.assertEqual(receiver.pool.submit.call_args.args[1], SID2)
        pending.set_exception(wake.Quarantined())
        with contextlib.redirect_stdout(io.StringIO()):
            receiver.tick()
        self.assertEqual(receiver.statuses[SID], 'quarantined')
        self.assertIn(SID2, receiver.futures)


class AutomaticStartTests(DispatcherTests, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.config = self.helper.root.parent
        self.config.chmod(0o700)
        self.account_file = self.config / 'trusted-account.json'
        wake.write_json(self.account_file, {'schema_version': 1, 'peer': self.helper.peer})

    def test_noncanonical_synthetic_account_never_launches_process(self):
        with patch.object(wake.subprocess, 'Popen') as spawn:
            self.assertFalse(wake.ensure_receiver(self.account_file))
        spawn.assert_not_called()

    def test_hook_only_starts_receiver_for_actual_root_start_or_real_work(self):
        from babel import lifecycle_dispatcher
        argv = ['account_lifecycle_hook.py', '--client', 'codex', '--account-file', str(self.account_file)]
        with patch.object(wake, 'ensure_receiver') as ensure, \
                patch.object(lifecycle_dispatcher.sys, 'argv', argv), \
                patch.dict(os.environ, {}, clear=True), \
                contextlib.redirect_stdout(io.StringIO()):
            lifecycle_dispatcher.main(raw=json.dumps({'hook_event_name': 'SessionStart',
                                                       'session_id': SID, 'source': 'startup'}).encode())
            ensure.assert_called_once_with(self.account_file)
            ensure.reset_mock()
            for data in (
                {'hook_event_name': 'SessionStart', 'session_id': SID, 'source': 'compact'},
                {'hook_event_name': 'SessionStart', 'session_id': SID, 'source': 'startup', 'agent_id': 'child'},
                {'hook_event_name': 'UserPromptSubmit', 'session_id': SID, 'turn_id': TURN,
                 'prompt': 'Babel mailbox notification for synthetic fixture. Message ID: synthetic-message.'},
            ):
                lifecycle_dispatcher.main(raw=json.dumps(data).encode())
            ensure.assert_not_called()

    def test_start_uses_single_inherited_lock_without_registration_or_systemd(self):
        socket_dir = self.root / '.codex/app-server-control'
        socket_dir.mkdir(mode=0o700, parents=True)
        path = socket_dir / 'app-server-control.sock'
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(path))
            path.chmod(0o600)
            with patch.object(wake.Path, 'home', return_value=self.root), \
                    patch.dict(os.environ, {'CODEX_HOME': str(self.root / '.codex')}), \
                    patch.object(wake.subprocess, 'Popen') as spawn:
                self.assertTrue(wake.ensure_receiver(self.account_file))
                self.assertIn('pass_fds', spawn.call_args.kwargs)
                self.assertNotIn('systemctl', spawn.call_args.args[0])
                info = path.stat()
                wake.write_json(self.config / 'account-wake-runtime.json', {'socket': [info.st_dev, info.st_ino]})
                with wake.locked(self.config / 'account-wake-runtime.lock'):
                    self.assertTrue(wake.ensure_receiver(self.account_file))
                self.assertEqual(spawn.call_count, 1)
        self.assertFalse(list(self.config.rglob('*registration*')))


class NativeFrameTests(unittest.TestCase):
    def ws(self, payload):
        ws = object.__new__(native.UnixWebSocket)
        ws.socket = Mock()
        ws.buffer = bytearray(payload)
        ws.deadline = time.monotonic() + 5
        return ws

    def frame(self, raw, opcode=1, final=True):
        return bytes([(128 if final else 0) | opcode, len(raw)]) + raw

    def test_fragmented_json_and_ping(self):
        ws = self.ws(self.frame(b'{"ok":', final=False) + self.frame(b'ping', opcode=9)
                     + self.frame(b'true}', opcode=0))
        self.assertEqual(ws.receive(), {'ok': True})
        ws.socket.sendall.assert_called_once()

    def test_oversized_or_masked_server_frame_is_rejected(self):
        for payload in (b'\x81\xff' + struct.pack('!Q', 8),
                        b'\x81\x7f' + struct.pack('!Q', native.LIMIT + 1)):
            with self.assertRaises(native.NativeUnavailable):
                self.ws(payload).receive()

    def test_trickled_frames_share_one_absolute_deadline(self):
        ws = self.ws(b'')
        clock = [0]
        chunks = iter(self.frame(b'{"ok":true}'))
        def trickle(count):
            clock[0] += 2
            return bytes([next(chunks)])
        ws.socket.recv.side_effect = trickle
        ws.deadline = 5
        with patch.object(native.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(native.NativeUnavailable):
                ws.receive()
        self.assertLessEqual(ws.socket.recv.call_count, 3)

    def test_expired_claim_never_calls_native_queue(self):
        instance = native.Native('/synthetic/socket', {'binary': '/synthetic/codex', 'target': '/synthetic/socket'})
        with patch.object(instance, 'metadata', return_value={'cwd': '/task'}), \
                patch.object(native.subprocess, 'run') as run:
            with self.assertRaises(native.NativeUnavailable):
                instance.queue(SID, '/task', 'Synthetic notice', time.time() + 1)
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
