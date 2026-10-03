"""Synthetic policy-controlled delivery; no live credentials or webhooks."""
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from babel.auth import Policy, ScopedStore
from babel.core import BridgeError, Store, MAX_HOPS, RATE_LIMIT
from babel.enrollment import change, edit
from babel.events import EventService, EVENT_NAME
from babel.mcp import dispatch
from tests.test_participants import fixture, wake, DOT, CODEX, GUEST, GROK
from tests.test_cloud import FakeTransport, KEY

class AutomaticApprovalTests(unittest.TestCase):
    def setUp(self):
        self.cfg=fixture();self.store=Store(':memory:')
    def tearDown(self):self.store.close()
    def stage(self,policy,source=DOT,recipient=GUEST,cid='chat_shared_01',mid='automatic-message-01',parent=None):
        scoped=ScopedStore(self.store,source,policy.agents[source][1],policy)
        return scoped.stage(source,recipient,text='selected synthetic content',message_id=mid,
                            conversation_id=cid,reply_to=parent,provenance='mcp')
    def test_conversation_auto_approval_queues_wake_and_idempotent_retry_once(self):
        self.cfg['conversations']['chat_shared_01']['approval']='automatic'
        policy=Policy(self.cfg);events=EventService(self.store,policy,wake(),FakeTransport())
        events.subscribe(GUEST,{'name':EVENT_NAME,'arguments':{'recipient':GUEST},
            'delivery':{'mode':'webhook','url':'https://guest.example.com/callback','secret':KEY}})
        row=self.stage(policy)['message']
        self.assertEqual(row['status'],'queued');self.assertIsNotNone(row['approved'])
        self.assertEqual(self.store.events(row['id'])[-1]['actor'],'automatic:chat_shared_01')
        self.assertEqual(len(self.store.inbox(GUEST)),1)
        self.assertTrue(self.stage(policy)['duplicate'])
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0],1)
        self.assertEqual(len(self.store.events(row['id'])),2)
        self.assertEqual(self.stage(policy,CODEX,GROK,'chat_private_01','manual-message-01')['message']['status'],'draft')
    def test_global_default_both_directions_and_conversation_manual_override(self):
        self.cfg['approval']='automatic';policy=Policy(self.cfg)
        parent=self.stage(policy)['message']
        reply=self.stage(policy,GUEST,DOT,mid='automatic-reply-01',parent=parent['id'])['message']
        self.assertEqual((parent['status'],reply['status']),('queued','queued'))
        self.cfg['conversations']['chat_private_01']['approval']='manual';policy=Policy(self.cfg)
        self.assertEqual(self.stage(policy,CODEX,GROK,'chat_private_01','manual-override-01')['message']['status'],'draft')
        # The same policy applies to explicitly selected trusted operator messages.
        result=self.store.stage(DOT,GUEST,text='operator-selected text',message_id='operator-automatic-01',conversation_id='chat_shared_01',policy=policy)
        self.assertEqual(result['message']['status'],'queued')
    def test_hot_toggle_preserves_subscription_and_existing_draft_and_approved_content(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'policy.json';path.write_text(json.dumps(self.cfg))
            policy=Policy.load(path);events=EventService(self.store,policy,wake(),FakeTransport())
            events.subscribe(GUEST,{'name':EVENT_NAME,'arguments':{'recipient':GUEST},
                'delivery':{'mode':'webhook','url':'https://guest.example.com/callback','secret':KEY}})
            subscriptions=[tuple(r) for r in self.store.db.execute('SELECT * FROM subscriptions')]
            scoped=ScopedStore(self.store,DOT,policy.agents[DOT][1],policy)
            args={'text':'selected','message_id':'pre-toggle-draft-01','conversation_id':'chat_shared_01'}
            self.assertEqual(scoped.stage(DOT,GUEST,**args)['message']['status'],'draft')
            edit(path,'approval',mode='automatic')
            self.assertEqual(Policy.load(path).agents,policy.agents)
            # Retrying an earlier draft does not retroactively approve unseen content.
            self.assertEqual(scoped.stage(DOT,GUEST,**args)['message']['status'],'draft')
            queued=scoped.stage(DOT,GUEST,**{**args,'message_id':'after-toggle-auto-01'})['message']
            self.assertEqual(queued['status'],'queued')
            edit(path,'approval',mode='manual')
            self.assertEqual(scoped.stage(DOT,GUEST,**{**args,'message_id':'after-toggle-manual-01'})['message']['status'],'draft')
            self.assertEqual(self.store._row(queued['id'])['status'],'queued')
            self.assertEqual(subscriptions,[tuple(r) for r in self.store.db.execute('SELECT * FROM subscriptions')])
    def test_global_auto_approval_keeps_route_identity_and_revocation_boundaries(self):
        self.cfg['approval']='automatic';policy=Policy(self.cfg)
        scoped=ScopedStore(self.store,DOT,policy.agents[DOT][1],policy)
        for source,recipient,cid in ((GUEST,DOT,'chat_shared_01'),(DOT,GROK,'chat_private_01')):
            with self.assertRaises(BridgeError):scoped.stage(source,recipient,text='denied',message_id='invalid-auto-route-01',conversation_id=cid)
        self.cfg['participants'][GUEST]['state']='revoked'
        with self.assertRaises(BridgeError):self.stage(Policy(self.cfg))
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM messages').fetchone()[0],0)
    def test_automatic_reply_chain_stops_at_global_hundred_hop_cap(self):
        self.cfg['approval']='automatic';policy=Policy(self.cfg)
        row=self.stage(policy)['message'];source,recipient=GUEST,DOT
        self.assertEqual(MAX_HOPS,100)
        start=time.time()
        for hop in range(2,MAX_HOPS+1):
            with patch('babel.core.time.time',return_value=start+hop*7):
                row=self.stage(policy,source,recipient,mid='automatic-hop-'+str(hop).zfill(8),parent=row['id'])['message']
            self.assertEqual(row['status'],'queued');source,recipient=recipient,source
        with patch('babel.core.time.time',return_value=start+(MAX_HOPS+1)*7):
            with self.assertRaises(BridgeError) as caught:self.stage(policy,source,recipient,mid='automatic-hop-denied',parent=row['id'])
        self.assertEqual(caught.exception.status,409)
        self.assertIn('hop limit',str(caught.exception))
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM messages').fetchone()[0],MAX_HOPS)
    def test_global_auto_approval_keeps_durable_owner_rate_limit(self):
        self.cfg['approval']='automatic';policy=Policy(self.cfg)
        for i in range(RATE_LIMIT):self.stage(policy,mid='automatic-rate-'+str(i).zfill(8))
        with self.assertRaises(BridgeError) as caught:self.stage(policy,CODEX,GROK,'chat_private_01','automatic-owner-rate')
        self.assertEqual(caught.exception.status,429)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM messages').fetchone()[0],RATE_LIMIT)
    def test_stage_and_approval_roll_back_together_if_wake_queue_fails(self):
        self.cfg['approval']='automatic'
        with patch.object(self.store,'_queue_wakes',side_effect=RuntimeError('synthetic storage failure')):
            with self.assertRaises(RuntimeError):self.stage(Policy(self.cfg))
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM messages').fetchone()[0],0)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],0)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0],0)
    def test_rpc_reports_queued_and_cli_validates_explicit_modes(self):
        cfg=change(self.cfg,'approval',mode='automatic');policy=Policy(cfg)
        scoped=ScopedStore(self.store,DOT,policy.agents[DOT][1],policy)
        response=dispatch(scoped,DOT,{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'stage_message','arguments':{
            'recipient':GUEST,'conversation_id':'chat_shared_01','text':'selected','message_id':'rpc-auto-message-01'}}})
        result=json.loads(response['result']['content'][0]['text'])
        self.assertEqual(result['message']['status'],'queued')
        self.assertEqual(change(cfg,'approval',mode='manual',conversation='chat_shared_01')['conversations']['chat_shared_01']['approval'],'manual')
        for value in (True,None,'yes',{},[]):
            bad=copy.deepcopy(self.cfg);bad['approval']=value
            with self.assertRaises(BridgeError):Policy(bad)
            bad=copy.deepcopy(self.cfg);bad['conversations']['chat_shared_01']['approval']=value
            with self.assertRaises(BridgeError):Policy(bad)
        with self.assertRaises(BridgeError):change(cfg,'approval',mode='automatic',conversation='unconfigured-chat')
