"""Native OpenCode plugin/bridge contracts, without providers or live accounts."""
import json
from pathlib import Path
import shutil
import subprocess
import time
import unittest
from unittest.mock import Mock

from babel.account_bootstrap import context
from babel.account_wake import Mailbox, Quarantined, Deferred, read_json
from babel.core import BridgeError
from babel.opencode_bridge import Bridge
from install_opencode_client import install
from tests.account_client_fixture import DispatcherTests

SID='ses_1234567890AbCdEfGhIjKlMnOp'
SID2='ses_1234567890AbCdEfGhIjKlMnOq'
TURN='msg_1234567890AbCdEfGhIjKlMnOp'
EMBER='bits255.dots.ada_20261002'


class OpenCodeTests(DispatcherTests,unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.bridge=Bridge.__new__(Bridge)
        self.bridge.root=self.helper.root.parent
        self.bridge.account_file=self.bridge.root/'trusted-account.json'
        self.bridge.helper=self.helper
        self.bridge.event({'session_id':SID,'hook_event_name':'session.created'})
        self.box=Mailbox(self.bridge.root,self.helper,SID,client='opencode')
        self.route={'recipient':EMBER,'conversation_id':'synthetic-conversation'}
        self.row={'id':'synthetic-native-wake','seq':1,'source':EMBER,'recipient':self.box.participant,
                  'conversation_id':self.route['conversation_id'],'text':'Private task body stays behind claim',
                  'status':'queued','created':10,'approved':10}
        self.helper.call=Mock(side_effect=self.remote)

    def remote(self,path,name,args,**kwargs):
        self.assertEqual(path,self.box.path)
        self.assertEqual(kwargs['expected_digest'],self.box.digest)
        if name=='list_contacts':return {'contacts':[self.route]}
        if name=='receive_messages':return {'messages':[self.row] if args['after']==0 else []}
        if name=='claim_message':return {'claimed':True,'claim_id':args['claim_id'],'message':self.row,'expires':time.time()+120}
        if name=='message_status':return {'message':self.row}
        raise AssertionError(name)

    def test_exact_native_context_case_sensitive_and_invalid_uuid_rejected(self):
        ctx=context('opencode',hook={'hook_event_name':'session.observed','session_id':SID})
        self.assertEqual(ctx['native_id'],SID)
        with self.assertRaises(BridgeError):context('opencode',hook={'hook_event_name':'session.observed','session_id':'12345678-1234-1234-1234-123456789012'})
        with self.assertRaises(BridgeError):context('opencode',hook={'hook_event_name':'SessionStart','session_id':SID})
        self.assertNotEqual(Mailbox(self.bridge.root,self.helper,SID,client='opencode').participant,'bits255.codex.auto_'+self.box.participant.rsplit('_',1)[1])

    def test_real_prompt_bootstraps_existing_native_context_and_never_persists_text(self):
        self.bridge.event({'session_id':SID2,'hook_event_name':'chat.message','message_id':TURN,'prompt':'Implement the private requested feature.'})
        records=self.records('opencode',SID2)
        self.assertEqual(sorted(r['kind'] for r in records),['bootstrap','turn'])
        self.assertNotIn('private requested',json.dumps(records))
        self.bridge.event({'session_id':SID2,'hook_event_name':'chat.message','message_id':TURN,'prompt':'Implement the private requested feature.'})
        self.assertEqual(len(self.records('opencode',SID2)),2)

    def test_subagent_and_maintenance_do_not_bootstrap_or_renew(self):
        self.assertEqual(self.bridge.event({'session_id':SID2,'hook_event_name':'session.created','parent_id':SID}),{'status':'ignored'})
        before=self.records('opencode',SID)
        self.bridge.event({'session_id':SID,'hook_event_name':'chat.message','message_id':TURN,'prompt':'Babel mailbox notification for worker'})
        self.assertEqual(self.records('opencode',SID),before)

    def test_native_acceptance_is_two_phase_no_duplicate_no_ack_no_peer_text(self):
        result=self.bridge.poll(SID)['notifications'][0]
        self.assertFalse(result['reconcile'])
        self.assertIn('native babel tool',result['text'])
        self.assertNotIn('account_session_helper.py',result['text'])
        self.assertNotIn(self.row['text'],result['text'])
        self.assertEqual(read_json(self.box.path/'account-wake-state.json')['submissions'][self.row['id']]['state'],'submitting')
        # A lost native response reconciles exact native message; never resubmit.
        retry=self.bridge.poll(SID)['notifications'][0]
        self.assertTrue(retry['reconcile'])
        self.assertEqual(result['native_message_id'],retry['native_message_id'])
        self.assertEqual(self.bridge.confirm(SID,retry),{'status':'accepted'})
        self.assertEqual(self.bridge.poll(SID),{'notifications':[]})
        names=[c.args[1] for c in self.helper.call.call_args_list]
        self.assertEqual(names.count('claim_message'),1)
        self.assertNotIn('acknowledge_message',names)

    def test_wrong_native_proof_and_changed_message_preserve_pending(self):
        request=self.bridge.poll(SID)['notifications'][0]
        with self.assertRaises(Quarantined):self.bridge.confirm(SID,{**request,'text':'altered'})
        self.row['text']='altered after reservation'
        with self.assertRaises(Quarantined):self.bridge.confirm(SID,request)
        self.assertTrue(self.bridge.poll(SID)['notifications'][0]['reconcile'])

    def test_polls_never_create_unknown_sessions_or_renew_lifecycle(self):
        before=set(self.helper.root.iterdir())
        with self.assertRaises(Deferred):self.bridge.poll(SID2)
        self.assertEqual(set(self.helper.root.iterdir()),before)
        records=self.records('opencode',SID)
        self.bridge.poll(SID)
        self.assertEqual(self.records('opencode',SID),records)

    def test_native_tool_uses_only_existing_exact_context_and_standard_helper(self):
        before=set(self.helper.root.iterdir())
        with self.assertRaises(OSError):self.bridge.tool(SID2,'list_contacts',{})
        self.assertEqual(set(self.helper.root.iterdir()),before)
        with self.assertRaises(BridgeError):self.bridge.tool(SID,'bootstrap',{})
        self.helper.call=Mock(return_value={'contacts':[self.route]})
        result=self.bridge.tool(SID,'list_contacts',{})
        self.assertEqual(result['contacts'],[self.route])
        self.helper.call.assert_called_once_with(self.box.path,'list_contacts',{})
        self.assertFalse(list(self.box.path.glob('*resume*')))

    def test_plugin_installer_dry_run_idempotence_and_edited_source_preservation(self):
        folder=self.root/'opencode/plugins'
        self.assertEqual(install(folder)['state'],'planned')
        self.assertFalse(folder.exists())
        self.assertEqual(install(folder,apply=True)['state'],'installed')
        self.assertEqual(install(folder,apply=True)['state'],'installed')
        plugin=folder/'babel-wake.js';plugin.write_text('// user edit')
        with self.assertRaises(ValueError):install(folder,apply=True)
        self.assertEqual(plugin.read_text(),'// user edit')

    @unittest.skipUnless(shutil.which('node'),'Node is required for native plugin contract tests')
    def test_native_plugin_contract(self):
        result=subprocess.run(['node','--test','tests/opencode_plugin.test.mjs'],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
