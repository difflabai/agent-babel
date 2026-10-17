"""Owner transport/config checks use synthetic accounts and local subprocesses."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from babel import account_enrollment as enrollment
from babel.core import BridgeError


class EnrollmentConfigurationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.root = self.home / '.config/255bits/agent-babel'
        self.root.mkdir(mode=0o700, parents=True)
        self.account = self.root / 'trusted-account.json'
        self.transport = self.root / enrollment.TRANSPORT_FILE
        self.owner = SimpleNamespace(pw_name='mikkel', pw_dir=str(self.home))
        self.write(self.account, {'schema_version': 1, 'peer': 'mikkel@pop-os'})
        for target, value in ((enrollment.pwd, self.owner), (enrollment.socket, 'pop-os')):
            attribute = 'getpwuid' if target is enrollment.pwd else 'gethostname'
            mocked = patch.object(target, attribute, return_value=value)
            mocked.start()
            self.addCleanup(mocked.stop)

    def write(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def enable(self):
        self.write(self.transport, {'schema_version': 1, 'enabled': True,
                                    'transport': 'pinned-ssh-operator'})

    def test_absent_or_disabled_transport_cannot_launch_or_create_state(self):
        with patch.object(enrollment.subprocess, 'Popen') as spawn:
            self.assertFalse(enrollment.ensure_enrollment(self.account))
            self.write(self.transport, {'schema_version': 1, 'enabled': False,
                                        'transport': 'pinned-ssh-operator'})
            self.assertFalse(enrollment.ensure_enrollment(self.account, fresh=True))
        spawn.assert_not_called()
        self.assertFalse((self.root / enrollment.STATE_DIRECTORY).exists())

    def test_noncanonical_account_is_rejected_before_metadata_read(self):
        with patch.object(enrollment, 'read_json') as read:
            with self.assertRaises(BridgeError):
                enrollment.Configuration(self.home / 'project/trusted-account.json')
        read.assert_not_called()

    def test_enabled_account_is_bound_to_real_uid_home_name_and_hostname(self):
        self.enable()
        config = enrollment.Configuration(self.account)
        self.assertTrue(config.enabled)
        self.assertEqual(config.peer, 'mikkel@pop-os')
        self.assertEqual(config.home, self.home)
        for owner, host in ((SimpleNamespace(pw_name='work', pw_dir=str(self.home)), 'pop-os'),
                            (self.owner, 'unapproved-host'),
                            (SimpleNamespace(pw_name='mikkel', pw_dir=str(self.home / 'other')), 'pop-os')):
            with patch.object(enrollment.pwd, 'getpwuid', return_value=owner), \
                    patch.object(enrollment.socket, 'gethostname', return_value=host):
                with self.assertRaises(BridgeError):
                    enrollment.Configuration(self.account)

    def test_caller_transport_or_peer_overrides_and_nonboolean_enable_are_rejected(self):
        base = {'schema_version': 1, 'enabled': True, 'transport': 'pinned-ssh-operator'}
        for data in (dict(base, peer='work@pop-os'), dict(base, command='other-command'),
                     dict(base, enabled='true'), dict(base, schema_version=True),
                     dict(base, transport='arbitrary-ssh')):
            self.write(self.transport, data)
            with self.assertRaises(BridgeError):
                enrollment.Configuration(self.account)

    def test_public_symlink_hardlink_and_duplicate_key_configuration_fail_closed(self):
        self.enable()
        self.transport.chmod(0o644)
        with self.assertRaises(BridgeError):
            enrollment.Configuration(self.account)
        self.transport.chmod(0o600)
        alias = self.root / 'linked-config.json'
        self.transport.rename(alias)
        self.transport.symlink_to(alias)
        with self.assertRaises(BridgeError):
            enrollment.Configuration(self.account)
        self.transport.unlink()
        os.link(alias, self.transport)
        with self.assertRaises(BridgeError):
            enrollment.Configuration(self.account)
        self.transport.unlink()
        alias.unlink()
        self.transport.write_text('{"schema_version":1,"enabled":false,"enabled":true,"transport":"pinned-ssh-operator"}')
        self.transport.chmod(0o600)
        with self.assertRaises(ValueError):
            enrollment.Configuration(self.account)
        with patch.object(enrollment.subprocess, 'Popen') as spawn:
            self.assertFalse(enrollment.ensure_enrollment(self.account, fresh=True))
        spawn.assert_not_called()


class EnrollmentTransportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)

    def run_synthetic(self, script, *, timeout=2):
        return enrollment.bounded_process([sys.executable, '-c', script], b'{"event":"synthetic"}\n',
                                          env=enrollment.ssh_environment(self.home), timeout=timeout)

    def test_transport_uses_fixed_operator_argv_and_json_stdin_with_safe_environment(self):
        payload = {'event_id': 'synthetic; do-not-execute', 'observed_at': 10}
        fake_environment = {'OPENAI_API_KEY': 'synthetic-provider-value',
                            'BABEL_SESSION_TOKEN': 'synthetic-mailbox-value',
                            'HOME': '/untrusted/home', 'SSH_AUTH_SOCK': '/synthetic/owner-agent'}
        with patch.dict(os.environ, fake_environment, clear=True), \
                patch.object(enrollment, 'bounded_process', return_value=b'{"state":"synthetic"}') as process:
            self.assertEqual(enrollment.SSHTransport(self.home).submit('mikkel@pop-os', payload),
                             {'state': 'synthetic'})
        argv, raw = process.call_args.args
        self.assertEqual(argv[0], '/usr/bin/ssh')
        self.assertEqual(argv[argv.index('-F') + 1], '/dev/null')
        self.assertEqual(argv[-3:], ['root@159.195.17.119',
                                    '/usr/local/sbin/agent-babel-trusted-session', 'mikkel@pop-os'])
        for option in ('StrictHostKeyChecking=yes', 'BatchMode=yes', 'ForwardAgent=no',
                       'PermitLocalCommand=no', 'ControlPath=none', 'RemoteCommand=none',
                       'ProxyCommand=none', 'ProxyJump=none', 'SendEnv=-*', 'Port=22'):
            self.assertIn(option, argv)
        self.assertNotIn(payload['event_id'], argv)
        self.assertEqual(json.loads(raw), payload)
        env = process.call_args.kwargs['env']
        self.assertEqual(set(env), {'HOME', 'PATH', 'LANG', 'LC_ALL', 'SSH_AUTH_SOCK'})
        self.assertEqual(env['HOME'], str(self.home))
        self.assertEqual(env['SSH_AUTH_SOCK'], '/synthetic/owner-agent')
        self.assertNotIn('shell', process.call_args.kwargs)

    def test_unapproved_peer_never_starts_transport(self):
        with patch.object(enrollment, 'bounded_process') as process:
            with self.assertRaises(BridgeError):
                enrollment.SSHTransport(self.home).submit('other@host', {})
        process.assert_not_called()

    def test_successful_synthetic_process_preserves_only_bounded_stdout(self):
        result = self.run_synthetic('import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())')
        self.assertEqual(result, b'{"event":"synthetic"}\n')

    def test_timeout_kills_synthetic_child_without_exposing_stderr(self):
        before = time.monotonic()
        with self.assertRaises(enrollment.TransportUnavailable) as raised:
            self.run_synthetic('import sys,time; sys.stdin.read(); '
                               'print("SYNTHETIC_PRIVATE_REPLY",file=sys.stderr,flush=True);time.sleep(3)', timeout=.15)
        self.assertLess(time.monotonic() - before, 2)
        self.assertNotIn('SYNTHETIC_PRIVATE_REPLY', str(raised.exception))

    def test_stdout_and_combined_output_limits_are_enforced_without_private_reply(self):
        for script, expected in (
            ('import sys;sys.stdin.read();sys.stdout.write("SYNTHETIC_PRIVATE_REPLY"+"x"*5000)', enrollment.OperatorRejected),
            ('import sys;sys.stdin.read();sys.stderr.write("SYNTHETIC_PRIVATE_REPLY"+"x"*20000)', enrollment.TransportUnavailable),
        ):
            with self.assertRaises(expected) as raised:
                self.run_synthetic(script)
            self.assertNotIn('SYNTHETIC_PRIVATE_REPLY', str(raised.exception))

    def test_ssh_exit255_is_transient_and_operator_denial_keeps_errors_private(self):
        for code, expected in ((255, enrollment.TransportUnavailable), (1, enrollment.OperatorRejected)):
            with self.assertRaises(expected) as raised:
                self.run_synthetic('import sys;sys.stdin.read();'
                                   'print("SYNTHETIC_PRIVATE_REPLY",file=sys.stderr);sys.exit(' + str(code) + ')')
            self.assertNotIn('SYNTHETIC_PRIVATE_REPLY', str(raised.exception))

    def test_malformed_operator_stdout_is_not_acceptance(self):
        with patch.object(enrollment, 'bounded_process', return_value=b'SYNTHETIC_PRIVATE_REPLY'):
            with self.assertRaises(enrollment.OperatorRejected) as raised:
                enrollment.SSHTransport(self.home).submit('mikkel@pop-os', {})
        self.assertNotIn('SYNTHETIC_PRIVATE_REPLY', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
