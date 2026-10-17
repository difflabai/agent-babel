"""Grok tests use synthetic hooks and bounded local control sockets, no models."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import socket
import struct
import threading
import time
import sys
import unittest
from unittest.mock import patch

from babel.account_bootstrap import context, local_key
from babel.core import BridgeError
from babel.grok_lifecycle import parse
from babel.native_lifecycle import parse as native_parse
from babel.grok_receiver import GrokNative, ControlSocket, LIMIT
from babel.native_receiver import NativeUnavailable, NativeRejected
from babel import account_wake as wake
from babel.lifecycle_dispatcher import main as lifecycle_main
from tests.account_client_fixture import DispatcherTests, SID, TURN, TURN2
from tests import test_native_receiver as native_fixture
from tests.test_native_receiver import exact
from tests import test_account_wake as delivery_fixture


def hook(name, **extra):
    events = {'SessionStart': 'session_start', 'UserPromptSubmit': 'user_prompt_submit', 'Stop': 'stop'}
    return {'hookEventName': events.get(name, name), 'sessionId': SID, **extra}


class GrokLifecycleTests(DispatcherTests, unittest.TestCase):
    def grok(self, name='SessionStart', **extra):
        return self.dispatcher.dispatch('grokbot', hook(name, **extra), env={})

    def test_exact_context_and_native_environment(self):
        ctx = context('grokbot', hook=hook('SessionStart', source='new'), env={'GROK_SESSION_ID': SID})
        self.assertEqual(ctx['native_id'], SID)
        self.assertNotEqual(local_key(self.helper.peer, ctx), local_key(self.helper.peer, dict(ctx, client='codex')))
        with self.assertRaises(BridgeError):
            context('grokbot', hook=hook('SessionStart'), env={'GROK_SESSION_ID': 'wrong-session'})
        with self.assertRaises(BridgeError):
            context('grokbot', hook=hook('SessionStart', session_id='different-session'), env={})
        with self.assertRaises(BridgeError):
            context('grokbot', hook=hook('SessionStart', hook_event_name='Stop'), env={})

    def test_native_new_load_duplicate_activity_and_no_transcript_persistence(self):
        self.grok(source='new')
        self.grok('UserPromptSubmit', promptId=TURN, prompt='Implement private selected task')
        self.assertEqual(len(self.records('grokbot')), 1)  # Prompt can still be blocked.
        self.grok('Stop', promptId=TURN, reason='end_turn', stopHookActive=False, lastAssistantMessage='private output')
        self.grok('Stop', promptId=TURN, reason='end_turn', stopHookActive=False)
        records = self.records('grokbot')
        self.assertEqual(len(records), 2)
        self.assertNotIn('private', json.dumps(records))
        self.grok(source='load'); self.grok(source='load')
        self.assertEqual(len([r for r in self.records('grokbot') if r['kind'] == 'resume']), 1)

    def test_wakes_subagents_failed_stops_and_compaction_cannot_renew(self):
        self.grok(source='new')
        self.grok('UserPromptSubmit', promptId=TURN, prompt='Babel mailbox notification for my participant')
        self.grok('Stop', promptId=TURN, reason='end_turn', stopHookActive=False)
        self.grok('UserPromptSubmit', promptId=TURN2, prompt='Do the selected change')
        self.grok('Stop', promptId=TURN2, reason='end_turn', stopHookActive=True)
        self.grok('Stop', promptId=TURN2, reason='error', stopHookActive=False)
        self.grok('Stop', reason='end_turn', stopHookActive=False)
        self.grok(source='compact')
        self.assertIsNone(parse(hook('SessionStart', source='new', subagentType='worker')))
        self.assertIsNone(parse(hook('UserPromptSubmit', promptId=TURN, subagentType='worker', prompt='Do work')))
        self.assertEqual(len(self.records('grokbot')), 1)

    def test_aliases_reject_contradictory_prompt_ids_and_stop_flags(self):
        for data in [hook('UserPromptSubmit', promptId=TURN, prompt_id=TURN2),
                     hook('Stop', promptId=TURN, reason='end_turn', stopHookActive=False, stop_hook_active=True)]:
            with self.assertRaises(BridgeError): parse(data)

    def test_compatible_claude_hooks_cannot_adopt_a_grok_session(self):
        data=hook('SessionStart',hook_event_name='SessionStart',session_id=SID,source='startup')
        self.assertIsNone(native_parse('claude',data,env={'GROK_SESSION_ID':SID}))
        self.assertIsNone(native_parse('codex',data,env={'GROK_HOOK_EVENT':'session_start'}))
        ordinary={'hook_event_name':'SessionStart','session_id':SID,'source':'startup'}
        self.assertEqual(native_parse('codex',ordinary,env={'GROK_SESSION_ID':SID})['client'],'codex')
        self.assertFalse(list(self.helper.root.iterdir()))

    def test_native_hook_stdout_never_blocks_or_continues_grok(self):
        self.helper.root.parent.chmod(0o700)
        account=self.helper.root.parent/'trusted-account.json'
        wake.write_json(account,{'schema_version':1,'peer':self.helper.peer})
        argv=['account_lifecycle_hook.py','--client','grokbot','--account-file',str(account)]
        for data in [hook('SessionStart',source='new'),
                     hook('UserPromptSubmit',promptId=TURN,prompt='Implement the requested task'),
                     hook('Stop',promptId=TURN,reason='end_turn',stopHookActive=False)]:
            output, errors=io.StringIO(),io.StringIO()
            with patch.object(sys,'argv',argv), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                lifecycle_main(raw=json.dumps(data).encode())
            self.assertEqual(json.loads(output.getvalue()),{})
            self.assertEqual(errors.getvalue(),'')


class GrokControlWireTests(unittest.TestCase):
    setUp = native_fixture.NativeWireTests.setUp
    # Reuse filesystem/peer-credential fixture setup, not Codex test cases.
    @contextlib.contextmanager
    def grok_peer(self, *, results=(), capability=True, ready=True, response_override=None):
        requests, errors = [], []
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path)); self.path.chmod(0o600); listener.listen(3); listener.settimeout(3)
        def send(stream, row):
            raw = json.dumps(row).encode(); stream.sendall(struct.pack('!I', len(raw)) + raw)
        def receive(stream):
            return json.loads(exact(stream, struct.unpack('!I', exact(stream, 4))[0]))
        def serve():
            try:
                for result in list(results) or [None]:
                    stream, _ = listener.accept()
                    with stream:
                        stream.settimeout(3)
                        register = receive(stream); requests.append(register)
                        self.assertEqual(register['type'], 'register')
                        self.assertEqual(register['capabilities'], {})
                        send(stream, {'type':'registered', 'ready':ready, 'leader_protocol_version':1,
                                      'leader_capabilities': {'control_v1':True, 'mailbox_notifications_v1':capability}})
                        if not capability or not ready:
                            self.assertEqual(stream.recv(1), b''); continue
                        control = receive(stream); requests.append(control)
                        self.assertEqual(control['type'], 'control')
                        row = {'type':'control_result', 'request_id':control['request_id'], 'result':{'Ok':result}}
                        send(stream, response_override or row)
            except BaseException as error:
                errors.append(error)
            finally:
                listener.close()
        thread = threading.Thread(target=serve, daemon=True); thread.start()
        try:
            yield requests
        finally:
            thread.join(4)
            if thread.is_alive(): self.fail('Synthetic Grok control peer did not finish')
            if errors: raise errors[0]

    def test_stock_grok_and_not_ready_fail_without_acp_or_controls(self):
        for capability, ready in [(False, True), (True, False)]:
            if self.path.exists(): self.path.unlink()
            with self.grok_peer(capability=capability, ready=ready) as requests:
                with self.assertRaises(NativeUnavailable): GrokNative(self.path).loaded()
            self.assertEqual([r['type'] for r in requests], ['register'])

    def test_live_metadata_and_queue_acceptance_are_control_only(self):
        notice = 'Babel mailbox notification for synthetic participant. No peer text.'
        nid = hashlib.sha256((SID+'\0'+notice).encode()).hexdigest()
        sessions = {'type':'mailbox_sessions','sessions':[{'id':SID,'cwd':'/synthetic/task'}]}
        ack = {'type':'mailbox_notification','session_id':SID,'notification_id':nid,'state':'queued'}
        with self.grok_peer(results=[sessions,sessions,ack]) as requests:
            native = GrokNative(self.path)
            self.assertEqual(native.loaded(),[SID])
            native.queue(SID,'/synthetic/task',notice,time.time()+120)
        self.assertEqual([r['type'] for r in requests], ['register','control']*3)
        self.assertEqual([r['command']['type'] for r in requests if r['type']=='control'],
                         ['mailbox_sessions','mailbox_sessions','queue_mailbox_notification'])
        self.assertNotIn('acp', json.dumps(requests))

    def test_busy_rejection_explicitly_allows_retry_but_pending_is_uncertain(self):
        notice='Babel mailbox notification for synthetic'
        nid=hashlib.sha256((SID+'\0'+notice).encode()).hexdigest()
        sessions={'type':'mailbox_sessions','sessions':[{'id':SID,'cwd':'/synthetic/task'}]}
        for state, error in [('busy',NativeRejected),('pending',NativeUnavailable)]:
            if self.path.exists(): self.path.unlink()
            ack={'type':'mailbox_notification','session_id':SID,'notification_id':nid,'state':state}
            with self.grok_peer(results=[sessions,ack]):
                with self.assertRaises(error): GrokNative(self.path).queue(SID,'/synthetic/task',notice,time.time()+120)

    def test_no_live_or_changed_cwd_rejects_before_mutation(self):
        result={'type':'mailbox_sessions','sessions':[]}
        with self.grok_peer(results=[result]) as requests:
            with self.assertRaises(NativeRejected): GrokNative(self.path).metadata(SID)
        self.assertEqual(len(requests),2)

    def test_reverse_request_never_answered_or_treated_as_ack(self):
        with self.grok_peer(results=[{}], response_override={'type':'acp','payload':'owner approval request'}) as requests:
            with self.assertRaises(NativeUnavailable): GrokNative(self.path).loaded()
        self.assertEqual(len(requests),2)

    def test_oversized_native_frame_fails_closed(self):
        with patch.object(ControlSocket, 'read', return_value=struct.pack('!I',LIMIT+1)):
            stream=object.__new__(ControlSocket)
            with self.assertRaises(NativeUnavailable): stream.receive()


class GrokDeliveryTests(delivery_fixture.AccountWakeTests):
    # These inherited tests exercise the same durable delivery boundaries for
    # Grok identities as Codex, including uncertain claims and crash recovery.
    def setUp(self):
        super().setUp()
        self.dispatcher.dispatch('grokbot',hook('SessionStart',source='new'),env={})
        self.box=wake.Mailbox(self.config,self.helper,SID,client='grokbot')
        self.rows[0]['recipient']=self.box.participant

    def test_notice_uses_native_grok_identity_and_never_a_coordinator_token(self):
        self.delivery().step()
        notice=self.native.queue.call_args.args[2]
        self.assertIn('--client grokbot',notice)
        self.assertIn('--native-session '+SID,notice)
        self.assertNotIn('--legacy-instance',notice)

    def test_explicit_busy_rejection_is_retryable_and_never_acknowledges(self):
        self.native.queue.side_effect=NativeRejected
        self.assertEqual(self.delivery().step(),0)
        self.assertEqual(wake.read_json(self.box.path/'account-wake-state.json')['submissions'],{})
        self.native.queue.side_effect=None
        self.assertEqual(self.delivery().step(),1)
        self.assertEqual(self.native.queue.call_count,2)

    def test_pending_rotation_waits_without_committing_candidate_or_network(self):
        pending=self.box.path/'resume-token';pending.write_text('synthetic-pending');pending.chmod(0o600)
        with self.assertRaises(wake.Deferred): wake.Mailbox(self.config,self.helper,SID,client='grokbot')
        self.helper.call.assert_not_called()

    def test_cross_session_manifest_and_recipient_are_rejected(self):
        path=self.box.path/'trusted-enrollment.json'
        manifest=wake.read_json(path);manifest['native_id']=TURN2;wake.write_json(path,manifest)
        with self.assertRaises(ValueError): wake.Mailbox(self.config,self.helper,SID,client='grokbot')

    def test_other_clients_cannot_be_adopted(self):
        self.assertNotEqual(self.box.participant,wake.Mailbox(self.config,self.helper,SID).participant)
