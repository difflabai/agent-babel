"""Bounded authentication readiness reads; no enrollment, models or real sleeps."""
from pathlib import Path
import io
import json
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from babel.account_enrollment import digest
from babel.account_wake import read_json
from babel.core import BridgeError
from babel.native_lifecycle import event_key
from babel.opencode_bridge import Bridge, contact_read, pending_bootstrap
from tests.account_client_fixture import DispatcherTests

SID='ses_syntheticReady123456789AB'


def http(code):return HTTPError('https://synthetic.invalid/',code,'synthetic-only',None,None)


class ContactReadTests(unittest.TestCase):
    def clock(self):
        current=[0.0];waits=[]
        def sleep(delay):waits.append(delay);current[0]+=delay
        return lambda:current[0],sleep,waits

    def test_only_pending401_reads_retry_then_return_authoritative_remote_success(self):
        clock,sleep,waits=self.clock();result={'contacts':[{'recipient':'synthetic.ember'}]}
        call=Mock(side_effect=[http(401),http(401),result]);pending=Mock(return_value='pending')
        self.assertIs(contact_read(call,pending,clock=clock,sleep=sleep),result)
        self.assertEqual(waits,[1,2]);self.assertEqual(call.call_count,3)

    def test_pending_deadline_is_bounded_and_explicitly_unverified(self):
        clock,sleep,waits=self.clock();call=Mock(side_effect=http(401))
        self.assertEqual(contact_read(call,lambda:'pending',clock=clock,sleep=sleep),
                         {'verified':False,'status':'awaiting_operator_enrollment','retry_after':20})
        self.assertEqual(sum(waits),12);self.assertEqual(waits,[1,2,3,4,2]);self.assertEqual(call.call_count,5)

    def test_accepted_revoked_network_and_local_failures_never_become_pending(self):
        for error,pending in [(http(401),False),(http(403),True),(http(429),True),
                              (TimeoutError(),True),(BridgeError('synthetic invalid config'),True)]:
            clock,sleep,waits=self.clock();call=Mock(side_effect=error)
            with self.subTest(error=type(error).__name__,code=getattr(error,'code',None)):
                with self.assertRaises(type(error)):contact_read(call,lambda:'pending' if pending else 'accepted',clock=clock,sleep=sleep)
                self.assertEqual(call.call_count,1);self.assertEqual(waits,[])

    def test_slow_reads_receive_only_the_remaining_overall_network_budget(self):
        now=[0.0];timeouts=[];waits=[]
        def call(*,timeout):
            timeouts.append(timeout);now[0]+=min(3,timeout);raise http(401)
        def sleep(delay):waits.append(delay);now[0]+=delay
        result=contact_read(call,lambda:'pending',clock=lambda:now[0],sleep=sleep)
        self.assertFalse(result['verified']);self.assertEqual(now[0],12)
        self.assertEqual(timeouts,[12,8,3]);self.assertEqual(waits,[1,2])
        now[0]=0
        def timeout(*,timeout):now[0]+=timeout;raise TimeoutError('synthetic network deadline')
        with self.assertRaises(TimeoutError):contact_read(timeout,lambda:'pending',clock=lambda:now[0],sleep=sleep)
        self.assertEqual(now[0],12) # Network failure is not a pending/success response.

    def test_acceptance_racing_first401_gets_one_immediate_authoritative_confirmation(self):
        clock,sleep,waits=self.clock();result={'contacts':[{'recipient':'synthetic.ember'}]}
        state=Mock(side_effect=['pending','accepted'])
        call=Mock(side_effect=[http(401),result])
        self.assertIs(contact_read(call,state,clock=clock,sleep=sleep),result)
        self.assertEqual(call.call_count,2);self.assertEqual(waits,[])
        state=Mock(side_effect=['pending','accepted','accepted']);call=Mock(side_effect=http(401))
        with self.assertRaises(HTTPError):contact_read(call,state,clock=clock,sleep=sleep)
        self.assertEqual(call.call_count,2) # Persistent accepted401 propagates.
        state=Mock(return_value='accepted');call=Mock(side_effect=http(401))
        with self.assertRaises(HTTPError):contact_read(call,state,clock=clock,sleep=sleep)
        self.assertEqual(call.call_count,1) # Already accepted on entry is never retried.

    def test_rotation_or_config_change_during_pending_read_is_not_retried(self):
        clock,sleep,waits=self.clock();call=Mock(side_effect=http(401))
        for state in (Mock(side_effect=['pending',None]),Mock(side_effect=['pending',BridgeError('changed evidence')])):
            call.reset_mock()
            with self.assertRaises((HTTPError,BridgeError)):contact_read(call,state,clock=clock,sleep=sleep)
            self.assertEqual(call.call_count,1);self.assertEqual(waits,[])


class PendingBootstrapTests(DispatcherTests,unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.bridge=Bridge.__new__(Bridge);self.bridge.root=self.helper.root.parent
        self.bridge.account_file=self.bridge.root/'trusted-account.json';self.bridge.helper=self.helper
        self.bridge.event({'session_id':SID,'hook_event_name':'session.created'})
        self.path=self.helper.path({'client':'opencode','native_id':SID})
        self.evidence=self.path/'lifecycle-events'/(event_key('bootstrap:'+SID)[7:]+'.json')

    def test_only_exact_fresh_unaccepted_bootstrap_is_pending(self):
        self.assertTrue(pending_bootstrap(self.path,SID))
        self.assertFalse(pending_bootstrap(self.path,'ses_othercontext123456789AB'))
        request=read_json(self.evidence)
        receipt=self.evidence.with_suffix('.receipt');receipt.write_text(digest(request)+'\n');receipt.chmod(0o600)
        self.assertFalse(pending_bootstrap(self.path,SID))
        receipt.write_text('corrupt\n')
        with self.assertRaises(BridgeError):pending_bootstrap(self.path,SID)

    def test_stale_or_rotating_contexts_are_not_new_pending_enrollment(self):
        with patch('babel.opencode_bridge.time.time',return_value=read_json(self.evidence)['observed_at']+86400):
            self.assertFalse(pending_bootstrap(self.path,SID))
        pending=self.path/'resume-token';pending.write_text('synthetic-only-uncommitted-credential');pending.chmod(0o600)
        self.assertFalse(pending_bootstrap(self.path,SID))

    def test_only_contacts_use_waiter_and_no_mutation_is_retried(self):
        self.helper.call=Mock(side_effect=http(401))
        with patch('babel.opencode_bridge.contact_read',return_value={'verified':False,'status':'awaiting_operator_enrollment','retry_after':20}) as waiting:
            result=self.bridge.tool(SID,'list_contacts',{})
            self.assertFalse(result['verified']);waiting.assert_called_once()
        for operation in ('stage_message','claim_message','acknowledge_message','stage_report'):
            self.helper.call.reset_mock()
            with patch('babel.opencode_bridge.contact_read') as waiting:
                with self.assertRaises(HTTPError):self.bridge.tool(SID,operation,{})
                self.helper.call.assert_called_once();waiting.assert_not_called()
        self.assertEqual(len(self.records('opencode',SID)),1) # No activity fabricated by tools.
        self.assertFalse(list(self.path.glob('*resume*')))


    def test_actual_tool_routing_pins_only_pending_reads_and_preserves_normal_calls(self):
        self.helper.call=Mock(return_value={'contacts':[]})
        self.bridge.tool(SID,'list_contacts',{})
        call=self.helper.call.call_args
        self.assertEqual(call.args,(self.path,'list_contacts',{}))
        self.assertEqual(call.kwargs['credential'],self.path/'token')
        self.assertEqual(call.kwargs['expected_digest'],read_json(self.evidence)['sha256'])
        self.assertGreater(call.kwargs['timeout'],0);self.assertLessEqual(call.kwargs['timeout'],12)
        receipt=self.evidence.with_suffix('.receipt');receipt.write_text(digest(read_json(self.evidence))+'\n');receipt.chmod(0o600)
        for rotating in (False,True):
            if rotating:
                candidate=self.path/'resume-token';candidate.write_text('synthetic-only-retained-candidate');candidate.chmod(0o600)
            self.helper.call.reset_mock();self.bridge.tool(SID,'list_contacts',{})
            self.helper.call.assert_called_once_with(self.path,'list_contacts',{})

    def test_helper_passes_bounded_network_timeout_to_existing_http_primitive(self):
        payload={'result':{'content':[{'text':json.dumps({'contacts':[]})}]}}
        with patch('account_session_helper.build_opener') as opener:
            opener.return_value.open.return_value=io.StringIO(json.dumps(payload))
            result=self.helper.call(self.path,'list_contacts',{},credential=self.path/'token',
                expected_digest=read_json(self.evidence)['sha256'],timeout=2.75)
            self.assertEqual(result,{'contacts':[]})
            self.assertEqual(opener.return_value.open.call_args.kwargs['timeout'],2.75)

    def test_nonobject_owned_json_is_a_local_evidence_failure(self):
        manifest_path=self.path/'trusted-enrollment.json'
        manifest=read_json(manifest_path);request=read_json(self.evidence)
        self.evidence.write_text('[]\n')
        with self.assertRaises(BridgeError):pending_bootstrap(self.path,SID)
        for invalid in (None,'0'*64,'A'*64,'invalid'):
            manifest_path.write_text(json.dumps({**manifest,'sha256':invalid}))
            self.evidence.write_text(json.dumps({**request,'sha256':invalid}))
            with self.subTest(digest=invalid):
                with self.assertRaises(BridgeError):pending_bootstrap(self.path,SID)
