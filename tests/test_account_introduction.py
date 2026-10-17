"""Fixed onboarding messages use synthetic authenticated boxes only."""
import copy
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from babel import account_introduction as intro
from babel.account_wake import Mailbox, Delivery
from babel.core import BridgeError
from tests import test_account_enrollment as fixture


class AccountIntroductionTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.AccountEnrollmentTests()
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture;self.f.enabled()
        path,request=self.f.event(client='opencode');folder=path.parent.parent
        token='SYNTHETIC-CREDENTIAL-ONLY'
        self.f.write(folder/'trusted-enrollment.json',dict(request,sha256=hashlib.sha256(token.encode()).hexdigest()))
        (folder/'token').write_text(token);(folder/'token').chmod(0o600)
        self.helper=SimpleNamespace(peer='mikkel@pop-os',root=self.f.root/'automatic-instances',call=Mock())
        self.box=Mailbox(self.f.root,self.helper,request['native_id'],client='opencode')
        key=self.box.participant.rsplit('auto_',1)[1]
        self.cid='report_auto_'+key+'_ember'
        self.contacts=[{'recipient':intro.EMBER,'conversation_id':self.cid}]
        self.history=[];self.accepted={};self.status='queued';self.fail_after_accept=False
        self.helper.call.side_effect=self.remote
        self.now=self.f.now

    def remote(self,path,name,args,**kwargs):
        self.assertEqual(path,self.box.path)
        self.assertEqual(kwargs['credential'],path/'token')
        self.assertEqual(kwargs['expected_digest'],self.box.digest)
        if name in ('bridge_history','stage_message'):self.assertEqual(kwargs['timeout'],5)
        if name=='bridge_history':return {'messages':copy.deepcopy(self.history)}
        if name=='stage_message':
            self.assertEqual(set(args),{'recipient','conversation_id','message_id','text'})
            duplicate=args['message_id'] in self.accepted
            row={'id':args['message_id'],'source':self.box.participant,'recipient':args['recipient'],
                 'conversation_id':args['conversation_id'],'text':args['text'],'reply_to':None,
                 'provenance':'mcp','status':self.status}
            if duplicate:self.assertEqual(self.accepted[row['id']],row)
            self.accepted[row['id']]=row
            if self.fail_after_accept:raise TimeoutError('PRIVATE-REMOTE-ERROR')
            return {'message':copy.deepcopy(row),'duplicate':duplicate}
        if name=='list_contacts':return {'contacts':self.contacts}
        if name=='receive_messages':return {'messages':[]}
        raise AssertionError(name)

    def run_intro(self):
        return intro.ensure_introduction(self.box,self.contacts,clock=lambda:self.now)

    def test_one_fixed_intro_and_restart_reuse_private_proof_without_remote_calls(self):
        self.assertEqual(self.run_intro(),'queued');calls=self.helper.call.call_count
        self.assertEqual(self.run_intro(),'queued');self.assertEqual(self.helper.call.call_count,calls)
        self.assertEqual(len(self.accepted),1)
        args=self.helper.call.call_args.args[2]
        self.assertEqual(args['text'],'Babel hello.');self.assertLess(len(args['text']),16)
        self.assertNotIn(self.box.sid,str(args));self.assertNotIn('SYNTHETIC-CREDENTIAL',str(args))
        self.assertEqual(set(self.box.path.iterdir()) & {self.box.path/'account-wake-state.json'},set())
        self.assertEqual((self.box.path/intro.LEDGER).stat().st_mode&0o777,0o600)

    def test_each_supported_native_client_keeps_its_exact_automatic_identity(self):
        for index,client in enumerate(('codex','claude','grokbot','opencode'),10):
            with self.subTest(client=client):
                path,request=self.f.event(index,client=client);folder=path.parent.parent
                token='SYNTHETIC-CLIENT-ONLY'
                self.f.write(folder/'trusted-enrollment.json',dict(request,sha256=hashlib.sha256(token.encode()).hexdigest()))
                (folder/'token').write_text(token);(folder/'token').chmod(0o600)
                self.box=Mailbox(self.f.root,self.helper,request['native_id'],client=client)
                self.cid='report_auto_'+self.box.participant.rsplit('auto_',1)[1]+'_ember'
                self.contacts=[{'recipient':intro.EMBER,'conversation_id':self.cid}]
                self.assertEqual(self.run_intro(),'queued')
                row=next(reversed(self.accepted.values()))
                self.assertEqual(row['source'],self.box.participant)
                self.assertEqual(row['conversation_id'],self.cid)

    def test_disabled_foreign_route_identity_and_legacy_paths_never_send(self):
        original=self.box.path
        for mutate,restore in [
            (lambda:self.f.enabled(False),lambda:self.f.enabled()),
            (lambda:setattr(self.box,'participant','bits255.opencode.legacy'),lambda:setattr(self.box,'participant','bits255.opencode.auto_'+self.cid[12:-6])),
            (lambda:setattr(self.box,'path',self.f.root/'instances/opencode-reviewed'),lambda:setattr(self.box,'path',original)),
        ]:
            participant=self.box.participant
            mutate();self.assertEqual(self.run_intro(),'disabled');restore();self.box.participant=participant
        for contacts in ([],self.contacts*2,[dict(self.contacts[0],recipient='bits255.grokbot.grok_20261002')],
                         [dict(self.contacts[0],conversation_id='foreign-conversation')]):
            self.assertEqual(intro.ensure_introduction(self.box,contacts),'disabled')
        self.helper.call.assert_not_called();self.assertFalse((original/intro.LEDGER).exists())

    def test_manifest_legacy_adoption_cannot_automatically_introduce(self):
        p=self.box.path/'trusted-enrollment.json';r=intro.read_json(p)
        r['existing_participant']=self.box.participant;self.f.write(p,r)
        self.assertEqual(self.run_intro(),'disabled');self.helper.call.assert_not_called()

    def own_row(self,status='queued'):
        return {'id':'already-existing-message','source':self.box.participant,'recipient':intro.EMBER,
                'conversation_id':self.cid,'provenance':'mcp','status':status,'text':'Owner selected existing message'}

    def test_existing_authenticated_outgoing_history_skips_duplicate_intro(self):
        self.history=[dict(self.own_row(),source=intro.EMBER,recipient=self.box.participant),self.own_row()]
        self.assertEqual(self.run_intro(),'existing');self.assertEqual(self.accepted,{})
        self.assertEqual(self.helper.call.call_count,1)
        self.assertEqual(self.run_intro(),'existing');self.assertEqual(self.helper.call.call_count,1)

    def test_existing_draft_is_awaiting_approval_and_never_duplicated(self):
        self.history=[self.own_row('draft')]
        self.assertEqual(self.run_intro(),'awaiting_approval');self.assertEqual(self.accepted,{})
        self.assertEqual(self.run_intro(),'awaiting_approval');self.assertEqual(self.helper.call.call_count,1)

    def test_stage_draft_stays_unapproved_and_is_not_called_a_wake(self):
        self.status='draft';self.assertEqual(self.run_intro(),'draft')
        state=intro.read_json(self.box.path/intro.LEDGER)
        self.assertEqual(state['state'],'draft');self.assertNotIn('ready',state)
        self.assertEqual(self.run_intro(),'draft');self.assertEqual(len(self.accepted),1)

    def test_ambiguous_stage_response_retries_same_id_body_after_durable_backoff(self):
        self.fail_after_accept=True
        self.assertEqual(self.run_intro(),'retry');state=intro.read_json(self.box.path/intro.LEDGER)
        self.assertEqual(state['state'],'pending');first=copy.deepcopy(self.accepted)
        calls=self.helper.call.call_count;self.assertEqual(self.run_intro(),'backoff')
        self.assertEqual(self.helper.call.call_count,calls)
        self.now+=21;self.fail_after_accept=False
        self.assertEqual(self.run_intro(),'queued');self.assertEqual(self.accepted,first)
        stages=[c.args[2] for c in self.helper.call.call_args_list if c.args[1]=='stage_message']
        self.assertEqual(stages[0],stages[1])

    def test_malformed_or_wrong_acceptance_never_publishes_success(self):
        original=self.helper.call.side_effect
        for field,value in [('source',intro.EMBER),('recipient',self.box.participant),('conversation_id','foreign-route'),
                            ('text','Different text'),('id','foreign-message'),('status','canceled'),('reply_to','foreign-parent')]:
            def bad(path,name,args,**kwargs):
                result=original(path,name,args,**kwargs)
                if name=='stage_message':result['message'][field]=value
                return result
            self.helper.call.side_effect=bad
            self.assertEqual(self.run_intro(),'retry')
            self.assertEqual(intro.read_json(self.box.path/intro.LEDGER)['state'],'pending')
            self.now+=301
        self.helper.call.side_effect=original

    def test_optout_during_history_stops_send_and_preserves_evidence(self):
        original=self.helper.call.side_effect
        def stop(path,name,args,**kwargs):
            result=original(path,name,args,**kwargs)
            if name=='bridge_history':self.f.enabled(False)
            return result
        self.helper.call.side_effect=stop
        self.assertEqual(self.run_intro(),'disabled');self.assertFalse(self.accepted)
        self.assertEqual(intro.read_json(self.box.path/intro.LEDGER)['state'],'pending')

    def test_concurrent_native_paths_share_one_nonblocking_introduction_lock(self):
        original=self.helper.call.side_effect
        def reentrant(path,name,args,**kwargs):
            if name=='stage_message':self.assertEqual(self.run_intro(),'busy')
            return original(path,name,args,**kwargs)
        self.helper.call.side_effect=reentrant
        self.assertEqual(self.run_intro(),'queued');self.assertEqual(len(self.accepted),1)

    def test_rotation_and_mismatched_private_ledger_fail_closed_without_send(self):
        (self.box.path/'resume-token').write_text('synthetic-pending');(self.box.path/'resume-token').chmod(0o600)
        self.assertEqual(self.run_intro(),'retry');self.assertFalse(self.accepted)
        (self.box.path/'resume-token').unlink()
        self.f.write(self.box.path/intro.LEDGER,{'schema_version':1,'participant':'foreign'})
        self.assertEqual(self.run_intro(),'retry');self.assertFalse(self.accepted)

    def test_introduction_failure_does_not_stop_shared_delivery_inbox_processing(self):
        native=Mock();native.metadata.return_value={'cwd':'/synthetic-only'}
        with patch.object(intro,'binding',side_effect=BridgeError('PRIVATE-INTERNAL-ERROR')):
            self.assertEqual(Delivery(self.box,native).step(),0)
        self.assertIn('receive_messages',[c.args[1] for c in self.helper.call.call_args_list])
        native.queue.assert_not_called()

    def test_oversized_or_foreign_history_never_becomes_an_introduction_proof(self):
        self.history=[dict(self.own_row(),conversation_id='foreign-route')]
        self.assertEqual(self.run_intro(),'retry');self.assertFalse(self.accepted)
        self.now+=301;self.history=[self.own_row()]*101
        self.assertEqual(self.run_intro(),'retry');self.assertFalse(self.accepted)
        self.now+=301
        self.history=[dict(self.own_row(),source=intro.EMBER,recipient=self.box.participant)]*100
        self.assertEqual(self.run_intro(),'retry');self.assertFalse(self.accepted)


if __name__=='__main__':unittest.main()
