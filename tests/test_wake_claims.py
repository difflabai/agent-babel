"""Recipient-claim wake gating and explicit external receiver limitations.

All model enqueue attempts are counted by a local stub. No network/model calls.
"""
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from babel.auth import Policy
from babel.core import Store
from babel.events import EventService
from babel.wake import CallbackError

class WakeClaimTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'bridge.sqlite3'
        self.store=Store(self.path)
        self.policy=Policy({'schema_version':1,'agents':{
            'ada':{'sha256':hashlib.sha256(b'public ada fixture').hexdigest(),'recipients':['grokbot']},
            'grokbot':{'sha256':hashlib.sha256(b'public grok fixture').hexdigest(),'recipients':['ada']}}})
        self.config=SimpleNamespace(grok_routines={},grok={'enabled':False},destination=lambda *args:None)
        self.service=EventService(self.store,self.policy,self.config,transport=object())
        with self.store.transaction():
            self.store.db.execute("""INSERT INTO subscriptions
                (id,role,url,secret,auth_digest,expires,verified_until,active,created)
                VALUES('synthetic-subscription','ada','https://invalid.example/callback','',?,?,0,1,?)""",
                (self.policy.agents['ada'][0],time.time()+86400,time.time()))
        self.turns=0
        self.fault=None
        self.dispatch=patch.object(self.service,'send_mcp',side_effect=self.receiver)
        self.dispatch.start()
    def tearDown(self):
        self.dispatch.stop();self.store.close();self.temp.cleanup()
    def receiver(self,s,row):
        self.turns+=1
        if self.fault:raise self.fault
        return 200,True
    def message(self):
        row=self.store.stage('grokbot','ada','public fixture',message_id='synthetic-approved-message')['message']
        return self.store.approve(row['id'])
    def expire(self):
        with self.store.transaction():self.store.db.execute('UPDATE message_claims SET expires=0')
    def test_empty_inbox_and_outbox_zero_turns(self):
        for _ in range(8):
            self.assertEqual(self.store.inbox('ada'),[])
            self.assertFalse(self.service.process_one())
        self.assertEqual(self.turns,0)
    def test_claimed_message_no_wake_and_expiry_reappears(self):
        row=self.message()
        self.store.claim_message(row['id'],'ada','synthetic-live-claim')
        for _ in range(8):
            self.assertEqual(self.store.inbox('ada'),[])
            self.assertFalse(self.service.process_one())
        self.assertEqual(self.turns,0)
        self.assertEqual(self.store.db.execute('SELECT attempts FROM outbox').fetchone()[0],0)
        self.expire()
        self.assertEqual(len(self.store.inbox('ada')),1)
        self.assertTrue(self.service.process_one())
        self.assertEqual(self.turns,1)
    def test_claim_after_notification_lease_defers_without_spending_attempt(self):
        row=self.message();original=self.service.claim
        def lease(now=None):
            notification=original(now)
            self.store.claim_message(row['id'],'ada','synthetic-racing-claim')
            return notification
        with patch.object(self.service,'claim',side_effect=lease):self.service.process_one()
        record=self.store.db.execute('SELECT * FROM outbox').fetchone()
        self.assertEqual((self.turns,record['status'],record['attempts']),(0,'pending',0))
        self.expire()
        with self.store.transaction():self.store.db.execute('UPDATE outbox SET next_attempt=0')
        self.service.process_one();self.assertEqual(self.turns,1)
    def test_acknowledged_message_and_delayed_dispatch_zero_turns(self):
        row=self.message()
        self.store.claim_message(row['id'],'ada','synthetic-ack-claim')
        self.store.acknowledge_claim(row['id'],'ada','synthetic-ack-claim')
        self.service.process_one()
        self.assertEqual(self.turns,0)
        self.assertEqual(self.store.inbox('ada'),[])
    def test_duplicate_outbox_insert_and_reconnect_one_turn(self):
        row=self.message()
        with self.store.transaction():
            for _ in range(8):self.store._queue_wakes(row)
        self.service.process_one()
        self.assertEqual(self.turns,1)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0],1)
        self.store.close();self.store=Store(self.path)
        self.service=EventService(self.store,self.policy,self.config,transport=object())
        with patch.object(self.service,'send_mcp',side_effect=self.receiver):
            for _ in range(8):self.assertFalse(self.service.process_one())
        self.assertEqual(self.turns,1)
    def test_canceled_message_zero_turns(self):
        row=self.message();self.store.cancel(row['id']);self.service.process_one()
        self.assertEqual(self.turns,0)
    def test_receiver_accept_then_timeout_requires_receiver_dedup(self):
        # Stable event IDs do not guarantee that an external receiver suppresses
        # model turns. This residual gap must block universal restart claims.
        self.message();self.fault=CallbackError('timeout')
        self.service.process_one();self.fault=None
        with self.store.transaction():self.store.db.execute('UPDATE outbox SET next_attempt=0')
        self.service.process_one()
        self.assertEqual(self.turns,2)
    def test_inflight_ack_requires_receiver_preflight(self):
        row=self.message()
        def delayed_receiver(s,event):
            self.store.claim_message(row['id'],'ada','synthetic-inflight-claim')
            self.store.acknowledge_claim(row['id'],'ada','synthetic-inflight-claim')
            self.assertEqual(self.store.inbox('ada'),[])
            return self.receiver(s,event)
        with patch.object(self.service,'send_mcp',side_effect=delayed_receiver):self.service.process_one()
        self.assertEqual(self.turns,1)  # Broker precheck alone cannot gate consumption.

if __name__=='__main__':unittest.main()
