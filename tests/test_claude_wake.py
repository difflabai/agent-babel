"""Synthetic native Claude launch/channel fixtures; never start a model."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

from babel import claude_wake as claude
from babel import account_wake as wake
from tests.account_client_fixture import DispatcherTests, SID, cli_command
import install_claude_launcher as installer

SID2 = '20000000-0000-4000-8000-000000000002'
EMBER = 'bits255.dots.ada_20261002'


class ClaudeWakeTests(DispatcherTests, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.hook(client='claude')
        self.config = self.helper.root.parent
        self.config.chmod(0o700)
        self.account = self.config / 'trusted-account.json'
        wake.write_json(self.account, {'schema_version': 1, 'peer': self.helper.peer})
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir(mode=0o700)
        self.native_identity = 'synthetic-native-runtime'
        self.parent_patch = patch.object(claude, 'invocation_context', return_value=self.native_identity)
        self.parent_patch.start()
        self.addCleanup(self.parent_patch.stop)
        wake.write_json(self.runtime / 'runtime.json', {'schema_version': 1, 'account_file': str(self.account),
                                                     'native_identity': self.native_identity})
        self.bind(SID)
        self.output = io.StringIO()
        self.channel = claude.Channel(self.account, self.runtime, self.output)

    def bind(self, sid):
        return claude.bind(self.account, {'hook_event_name': 'SessionStart', 'session_id': sid,
                                         'source': 'startup'}, {claude.ENV: str(self.runtime)})

    def test_no_launcher_no_binding_no_registration(self):
        before = set(self.runtime.iterdir())
        self.assertFalse(claude.bind(self.account, {}, {}))
        self.assertEqual(before, set(self.runtime.iterdir()))
        self.assertFalse(list(self.config.rglob('*registration*')))

    def test_bound_actual_uuid_is_required_and_changed_session_cannot_emit(self):
        with self.assertRaises(wake.Deferred):
            self.channel.metadata(SID2)
        self.bind(SID2)
        with self.assertRaises(wake.Deferred):
            self.channel.queue(SID, '', 'must not emit', time.time() + 100)
        self.assertEqual(self.output.getvalue(), '')
        self.assertEqual(self.channel.metadata(SID2)['id'], SID2)
        for source in ('resume', 'clear', 'fork'):
            self.assertTrue(claude.bind(self.account, {'hook_event_name': 'SessionStart',
                'session_id': SID, 'source': source}, {claude.ENV: str(self.runtime)}))

    def test_invalid_hosted_or_wrong_account_runtime_fails_closed(self):
        for data, env in [({'hook_event_name': 'UserPromptSubmit', 'session_id': SID}, {}),
                          ({'hook_event_name': 'SessionStart', 'session_id': SID, 'source': 'startup'},
                           {'CLAUDE_CODE_REMOTE': 'true'})]:
            with self.assertRaises(ValueError):
                claude.bind(self.account, data, {claude.ENV: str(self.runtime), **env})
        with self.assertRaises(ValueError):
            claude.runtime(self.runtime, self.config / 'other-account.json')
        with patch.object(claude, 'invocation_context', return_value='another-native-runtime'):
            with self.assertRaises(ValueError):
                self.bind(SID2)
        self.assertEqual(self.channel.binding(), SID)

    def test_session_without_mailbox_does_not_create_credentials(self):
        self.bind(SID2)
        before = set(self.helper.root.iterdir())
        with self.assertRaises(wake.Deferred):
            self.channel.tick()
        self.assertEqual(before, set(self.helper.root.iterdir()))

    def test_legacy_protocol_and_one_way_channel_without_permission_relay(self):
        self.channel.pump = Mock()
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                   'params': {'protocolVersion': '2026-07-28'}}
        result = self.channel.handle(request)['result']
        self.assertEqual(result['protocolVersion'], '2025-11-25')
        self.assertEqual(result['capabilities'], {'experimental': {'claude/channel': {}}})
        self.assertIn('actual SessionStart UUID', result['instructions'])
        self.assertIn('skip without claiming or reading', result['instructions'])
        self.assertIsNone(self.channel.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'}))
        self.channel.thread.join(1)
        self.channel.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        self.channel.pump.assert_called_once()
        self.assertEqual(self.channel.handle({'jsonrpc': '2.0', 'id': 2,
            'method': 'tools/call', 'params': {'name': 'arbitrary'}})['error']['code'], -32601)
        self.assertEqual(self.channel.handle(request)['error']['code'], -32601)

    def test_malformed_and_oversized_mcp_frames_do_not_start_receiver(self):
        self.channel.pump = Mock()
        claude.stdio(self.channel, io.BytesIO(b'not-json\n[]\n'))
        self.assertEqual(len(self.output.getvalue().splitlines()), 2)
        self.channel.pump.assert_not_called()
        with self.assertRaises(ValueError):
            claude.stdio(self.channel, io.BytesIO(b'x' * (claude.MAX_FRAME + 1)))

    def remote(self, path, name, args, **kwargs):
        self.calls.append(name)
        self.assertEqual(path.name.split('-')[0], 'claude')
        self.assertEqual(kwargs['credential'], path / 'token')
        if name == 'list_contacts':
            return {'contacts': [{'recipient': EMBER, 'conversation_id': 'synthetic-route'}]}
        if name == 'receive_messages':
            return {'messages': [] if args['after'] else self.rows}
        if name == 'claim_message':
            return {'claimed': True, 'claim_id': args['claim_id'], 'message': self.rows[0],
                    'expires': time.time() + 120}
        if name == 'message_status':
            return {'message': self.rows[0]}
        raise AssertionError(name)

    def prepare_delivery(self):
        self.calls = []
        box = wake.Mailbox(self.config, self.helper, SID, client='claude')
        self.rows = [{'id': 'synthetic-claude-wake', 'seq': 1, 'source': EMBER,
            'recipient': box.participant, 'conversation_id': 'synthetic-route', 'text': 'PRIVATE TASK BODY',
            'created': 10, 'approved': 10, 'status': 'queued'}]
        self.channel.helper.call = Mock(side_effect=self.remote)

    def test_native_emission_reserves_claim_dedupes_and_does_not_ack_or_include_body(self):
        self.prepare_delivery()
        self.assertEqual(self.channel.tick(), 1)
        self.assertEqual(self.channel.tick(), 0)
        value = json.loads(self.output.getvalue())
        self.assertEqual(value['method'], 'notifications/claude/channel')
        self.assertEqual(value['params']['meta']['native_session'], SID)
        text = value['params']['content']
        self.assertIn('--client claude', text)
        self.assertIn('--native-session ' + SID, text)
        self.assertIn('Reserved claim ID: wake_', text)
        self.assertIn('actual SessionStart UUID', text)
        self.assertIn('skip without claiming or reading', text)
        self.assertNotIn('PRIVATE TASK BODY', text)
        self.assertNotIn('acknowledge_message', self.calls)
        self.assertFalse(list(self.config.rglob('account-wake-state.json')))

    def test_fresh_runtime_replays_unacked_ids_and_uncertain_same_runtime_is_quarantined(self):
        self.prepare_delivery()
        with patch.object(self.channel, 'write', side_effect=BrokenPipeError):
            with self.assertRaises(BrokenPipeError):
                self.channel.tick()
        with self.assertRaises(wake.Quarantined):
            self.channel.tick()
        # A fresh native launch has no false permanent accepted-delivery mark.
        (self.runtime / (SID + '.json')).unlink()
        self.assertEqual(self.channel.tick(), 1)

    def test_noncoordinator_and_removed_route_cannot_emit(self):
        self.prepare_delivery()
        self.rows[0]['source'] = 'synthetic.untrusted'
        self.assertEqual(self.channel.tick(), 0)
        self.assertNotIn('claim_message', self.calls)
        self.assertEqual(self.output.getvalue(), '')

    def test_actual_hook_subprocess_binds_uuid_and_keeps_fast_prompt_path(self):
        script = Path(__file__).resolve().parents[1] / 'account_lifecycle_hook.py'
        wake.write_json(self.runtime / 'runtime.json', {'schema_version': 1, 'account_file': str(self.account),
                                                     'native_identity': claude.process_identity(os.getpid())})
        env = {**os.environ, claude.ENV: str(self.runtime)}
        result = subprocess.run(cli_command(script, self.account), input=json.dumps({
            'hook_event_name': 'SessionStart', 'session_id': SID2, 'source': 'startup'}),
            text=True, capture_output=True, env=env, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertEqual(self.channel.binding(), SID2)
        before = (self.runtime / 'binding.json').read_bytes()
        result = subprocess.run(cli_command(script, self.account), input=json.dumps({
            'hook_event_name': 'UserPromptSubmit', 'session_id': SID2, 'prompt': 'Make the requested change.'}),
            text=True, capture_output=True, env=env, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.runtime / 'binding.json').read_bytes(), before)

    def test_native_launcher_fixture_gets_channel_and_preserves_cli_args_and_exit(self):
        native = self.root / 'synthetic-claude'
        result_file = self.root / 'native-result.json'
        repo = Path(__file__).resolve().parents[1]
        native.write_text('#!' + sys.executable + '\nimport json,os,sys,subprocess\nfrom pathlib import Path\n'
            + 'sys.path.insert(0,' + repr(str(repo)) + ')\nfrom tests.account_client_fixture import cli_command\n'
            + 'p=Path(os.environ[' + repr(claude.ENV) + '])\n'
            + 'import time\nwhile json.loads((p/"runtime.json").read_text())["native_identity"] is None:time.sleep(.01)\n'
            + 'hook=subprocess.run(cli_command(Path(' + repr(str(repo / 'account_lifecycle_hook.py')) + '),Path('
            + repr(str(self.account)) + ')),input=json.dumps({"hook_event_name":"SessionStart","session_id":'
            + repr(SID2) + ',"source":"startup"}),capture_output=True,text=True,timeout=3)\n'
            + 'assert hook.returncode==0 and not hook.stderr,hook.stderr\n'
            + 'Path(' + repr(str(result_file)) + ').write_text(json.dumps({"argv":sys.argv[1:],'
            + '"runtime":str(p),"manifest":json.loads((p/"runtime.json").read_text()),'
            + '"binding":json.loads((p/"binding.json").read_text())}))\nsys.exit(17)\n')
        native.chmod(0o700)
        with patch.object(claude.sys.stdin, 'isatty', return_value=True):
            self.assertEqual(claude.launch(native, self.account, ['--model', 'synthetic', 'hello world']), 17)
        result = json.loads(result_file.read_text())
        self.assertFalse(Path(result['runtime']).exists())
        self.assertIsNotNone(result['manifest']['native_identity'])
        self.assertEqual(result['binding'], {'native_id': SID2})
        argv = result['argv']
        self.assertEqual(argv[:3], ['--model', 'synthetic', 'hello world'])
        self.assertEqual(argv[-2:], ['--dangerously-load-development-channels', 'server:' + claude.SERVER])
        config = json.loads(argv[4])['mcpServers'][claude.SERVER]
        self.assertIn(result['runtime'], config['args'])
        self.assertFalse(any('permission' in arg for arg in argv))

    def test_variadic_channel_options_never_consume_user_prompt(self):
        for args in (['hello world'], ['--', 'hello world']):
            child = Mock(pid=os.getpid())
            child.wait.return_value = 0
            with patch.object(claude.sys.stdin, 'isatty', return_value=True), patch.object(claude.subprocess, 'Popen', return_value=child) as call:
                claude.launch('/synthetic/claude', self.account, args)
            argv = call.call_args.args[0]
            if '--' in args:
                self.assertEqual(argv[-2:], ['--', 'hello world'])
            else:
                self.assertEqual(argv[:2], ['/synthetic/claude', 'hello world'])

    def test_variadic_user_mcp_configs_and_custom_channel_options_are_preserved(self):
        args = ['task', '--mcp-config', '/one.json', '/two.json', '--model', 'synthetic',
                '--mcp-config={"mcpServers":{}}', '--dangerously-load-development-channels',
                'server:user_owned', '--channels', 'plugin:approved@marketplace']
        result = claude.launch_args(args, {'mcpServers': {claude.SERVER: {}}})
        self.assertEqual(result[:3], ['task', '--model', 'synthetic'])
        self.assertEqual(result.count('--mcp-config'), 1)
        self.assertEqual(result.count('--dangerously-load-development-channels'), 1)
        self.assertIn('/one.json', result)
        self.assertIn('/two.json', result)
        self.assertIn('{"mcpServers":{}}', result)
        self.assertIn('server:user_owned', result)
        self.assertEqual(result[3:5], ['--channels', 'plugin:approved@marketplace'])
        self.assertEqual(result[-1], 'server:' + claude.SERVER)

    def test_print_and_administrative_modes_do_not_claim_channel_support(self):
        for args in (['-p', 'hi'], ['--print=json', 'hi'], ['--version'], ['mcp', 'list'],
                     ['--bg', 'task'], ['--bare'], ['--init-only']):
            with patch.object(claude.subprocess, 'call', return_value=0) as call:
                self.assertEqual(claude.launch('/synthetic/claude', self.account, args), 0)
            self.assertEqual(call.call_args.args[0], ['/synthetic/claude', *args])
            self.assertNotIn('env', call.call_args.kwargs)
        with patch.object(claude.sys.stdin, 'isatty', return_value=False), patch.object(claude.subprocess, 'call') as call:
            claude.launch('/synthetic/claude', self.account, ['piped prompt'])
        self.assertEqual(call.call_args.args[0], ['/synthetic/claude', 'piped prompt'])

    def test_launcher_installer_is_explicit_idempotent_and_preserves_native_and_settings(self):
        native = self.root / 'native'
        native.write_text('#!/bin/sh\nexit 0\n')
        native.chmod(0o700)
        client_dir = Path(__file__).resolve().parents[1]
        target = self.root / 'private-bin' / 'claude'
        # Source check intentionally wants a private installed entrypoint.
        client = self.root / 'client'
        client.mkdir(mode=0o700)
        entry = client / 'claude_wake.py'
        entry.write_text('# synthetic installed entry\n')
        entry.chmod(0o600)
        result = installer.install(target, native, self.account, client)
        self.assertEqual(result['state'], 'planned')
        self.assertFalse(target.parent.exists())
        before = native.read_bytes()
        installer.install(target, native, self.account, client, apply=True)
        installer.install(target, native, self.account, client, apply=True)
        self.assertEqual(native.read_bytes(), before)
        self.assertIn('"$@"', target.read_text())
        target.write_text('# unrelated local edit\n')
        with self.assertRaises(ValueError):
            installer.install(target, native, self.account, client, apply=True)
        self.assertEqual(target.read_text(), '# unrelated local edit\n')
        with self.assertRaises(ValueError):
            installer.install(native, native, self.account, client, apply=True)


if __name__ == '__main__':
    unittest.main()
