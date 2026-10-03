"""Bounded synthetic reply chains; no live agents, credentials or callbacks."""
import copy
from email.message import Message
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
from babel import mcp2
from tests.test_participants import fixture, wake, DOT, GUEST, CODEX, GROK
from tests.test_cloud import FakeTransport, KEY


class ConversationHopTests(unittest.TestCase):
    def setUp(self):
        self.cfg = fixture()
        self.cfg['approval'] = 'automatic'
        self.store = Store(':memory:')

    def tearDown(self):
        self.store.close()

    def stage(self, policy, source, recipient, cid, mid, parent=None):
        return ScopedStore(self.store, source, policy.agents[source][1], policy).stage(
            source, recipient, text='bounded synthetic hop test', message_id=mid,
            conversation_id=cid, reply_to=parent, provenance='mcp')['message']

    def chain(self, policy, cid, source, recipient, cap, prefix):
        row = None
        latest = self.store.db.execute('SELECT MAX(created) FROM messages').fetchone()[0]
        start = max(time.time(), latest or 0)
        for hop in range(1, cap + 1):
            # Respect the unchanged durable ten-per-owner/minute limit.
            with patch('babel.core.time.time', return_value=start + hop * 7):
                row = self.stage(policy, source, recipient, cid, prefix + '-%03d' % hop,
                                 row['id'] if row else None)
            self.assertEqual((row['hops'], row['status']), (hop, 'queued'))
            source, recipient = recipient, source
        with patch('babel.core.time.time', return_value=start + (cap + 1) * 7):
            with self.assertRaises(BridgeError) as caught:
                self.stage(policy, source, recipient, cid, prefix + '-denied', row['id'])
        self.assertEqual(caught.exception.status, 409)
        self.assertIn('hop limit', str(caught.exception))
        return row

    def event_definition(self, policy, role):
        events = EventService(self.store, policy, wake(), FakeTransport())
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'events/list', 'params': {'_meta': {
            mcp2.PREFIX + 'protocolVersion': mcp2.VERSION,
            mcp2.PREFIX + 'clientCapabilities': {}}}}
        headers = Message()
        headers['MCP-Protocol-Version'] = mcp2.VERSION
        headers['Mcp-Method'] = 'events/list'
        code, response = mcp2.dispatch(
            ScopedStore(self.store, role, policy.agents[role][1], policy), role,
            request, events, headers)
        self.assertEqual(code, 200)
        return response['result']['events'][0]

    def test_global_hundred_applies_without_overrides_to_all_conversations(self):
        policy = Policy(self.cfg)
        self.assertEqual(MAX_HOPS,100)
        self.assertTrue(all(policy.hop_limit(cid)==100 for cid in policy.conversations))
        self.chain(policy, 'chat_shared_01', DOT, GUEST, 100, 'global-hop')
        self.chain(policy, 'chat_private_01', CODEX, GROK, MAX_HOPS, 'default-hop')
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM messages').fetchone()[0], 200)

    def test_legacy_global_hundred_and_rejection_at_hop_101(self):
        from tests.test_cloud import policy
        p = policy()
        self.assertEqual(p.hop_limit(None), MAX_HOPS)
        legacy_two = Policy({'schema_version': 2, 'agents': {
            role: {'sha256': p.credential_digests[role], 'recipients': sorted(entry[1])}
            for role, entry in p.agents.items()}})
        self.assertEqual(legacy_two.hop_limit(None), 100)
        self.assertEqual(self.event_definition(legacy_two, 'ada')['payloadSchema']['properties']['hops']['maximum'], 100)
        row = None
        start = time.time()
        source, recipient = 'ada', 'grokbot'
        for hop in range(1, MAX_HOPS + 1):
            with patch('babel.core.time.time',return_value=start+hop*7):
                row = self.stage(p, source, recipient, None, 'legacy-hop-%03d' % hop,
                                 row['id'] if row else None)
            row = self.store.approve(row['id'])
            source, recipient = recipient, source
        with patch('babel.core.time.time',return_value=start+(MAX_HOPS+1)*7):
            with self.assertRaises(BridgeError) as caught:
                self.stage(p, source, recipient, None, 'legacy-hop-denied', row['id'])
        self.assertEqual(caught.exception.status,409)
        self.assertIn('hop limit',str(caught.exception))

    def test_more_than_four_hops_produce_valid_recipient_event_payloads(self):
        policy = Policy(self.cfg)
        service = EventService(self.store, policy, wake(), FakeTransport())
        service.subscribe(GUEST, {'name': EVENT_NAME, 'arguments': {'recipient': GUEST},
            'delivery': {'mode': 'webhook', 'url': 'https://guest.example.com/callback', 'secret': KEY}})
        row = None
        source, recipient = DOT, GUEST
        for hop in range(1, 6):
            row = self.stage(policy, source, recipient, 'chat_shared_01', 'event-hop-%03d' % hop,
                             row['id'] if row else None)
            source, recipient = recipient, source
        schema = self.event_definition(policy, GUEST)['payloadSchema']
        self.assertEqual(schema['properties']['hops']['maximum'], 100)
        self.assertEqual(self.event_definition(policy, CODEX)['payloadSchema']['properties']['hops']['maximum'], 100)
        body = json.loads(self.store.db.execute('SELECT body FROM outbox WHERE message_id=?', (row['id'],)).fetchone()[0])
        payload = body['data']
        self.assertEqual(payload['hops'], 5)
        self.assertEqual(set(payload), set(schema['required']))
        self.assertLessEqual(payload['hops'], schema['properties']['hops']['maximum'])

    def test_higher_limit_retains_owner_rate_limit_and_route_controls(self):
        self.cfg['conversations']['chat_shared_01']['max_hops'] = 100
        policy = Policy(self.cfg)
        for n in range(RATE_LIMIT):
            self.stage(policy, DOT, GUEST, 'chat_shared_01', 'rate-hop-%03d' % n)
        with self.assertRaises(BridgeError) as caught:
            self.stage(policy, CODEX, GROK, 'chat_private_01', 'owner-rate-denied')
        self.assertEqual(caught.exception.status, 429)
        with self.assertRaises(BridgeError) as caught:
            self.stage(policy, DOT, GROK, 'chat_shared_01', 'route-hop-denied')
        self.assertEqual(caught.exception.status, 403)

    def test_limit_hot_edit_preserves_identity_callbacks_and_existing_messages(self):
        self.cfg['conversations']['chat_shared_01']['max_hops'] = 4
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'policy.json'
            path.write_text(json.dumps(self.cfg))
            old = Policy.load(path)
            service = EventService(self.store, old, wake(), FakeTransport())
            service.subscribe(GUEST, {'name': EVENT_NAME, 'arguments': {'recipient': GUEST},
                'delivery': {'mode': 'webhook', 'url': 'https://guest.example.com/callback', 'secret': KEY}})
            scoped = ScopedStore(self.store, DOT, old.agents[DOT][1], old)
            scoped.stage(DOT, GUEST, text='retained', message_id='retained-hop-parent', conversation_id='chat_shared_01')
            messages = [tuple(r) for r in self.store.db.execute('SELECT * FROM messages')]
            subscriptions = [tuple(r) for r in self.store.db.execute('SELECT * FROM subscriptions')]
            edit(path, 'hop-limit', conversation='chat_shared_01', max_hops=100)
            new = Policy.load(path)
            self.assertEqual(old.agents, new.agents)
            scoped.guard()
            self.assertEqual(scoped.policy.hop_limit('chat_shared_01'), 100)
            self.assertEqual(new.hop_limit('chat_private_01'), 100)
            self.assertEqual(messages, [tuple(r) for r in self.store.db.execute('SELECT * FROM messages')])
            self.assertEqual(subscriptions, [tuple(r) for r in self.store.db.execute('SELECT * FROM subscriptions')])
            self.assertEqual(self.event_definition(new, GUEST)['payloadSchema']['properties']['hops']['maximum'], 100)

    def test_invalid_limits_rejected_and_no_global_operation(self):
        for value in (True, False, None, 0, 101, -1, 4.5, '100', {}, []):
            cfg = copy.deepcopy(self.cfg)
            cfg['conversations']['chat_shared_01']['max_hops'] = value
            with self.subTest(value=value), self.assertRaises(BridgeError):
                Policy(cfg)
        for value in (1, 4, 100):
            changed = change(self.cfg, 'hop-limit', conversation='chat_shared_01', max_hops=value)
            self.assertEqual(Policy(changed).hop_limit('chat_shared_01'), value)
        self.assertNotIn('max_hops', self.cfg['conversations']['chat_shared_01'])
        with self.assertRaises(BridgeError):
            change(self.cfg, 'hop-limit', conversation='missing-chat', max_hops=100)

    def test_event_limit_ignores_ungranted_and_closed_conversations(self):
        self.cfg['conversations']['chat_private_01']['max_hops'] = 100
        self.cfg['conversations']['chat_private_01']['routes'] = []
        self.assertEqual(Policy(self.cfg).event_hop_limit(CODEX), 100)
        self.cfg['conversations']['chat_shared_01']['max_hops'] = 100
        self.cfg['conversations']['chat_shared_01']['state'] = 'closed'
        self.assertEqual(Policy(self.cfg).event_hop_limit(DOT), 100)

    def test_existing_explicit_lower_limit_remains_backwards_compatible(self):
        self.cfg['conversations']['chat_shared_01']['max_hops'] = 4
        policy=Policy(self.cfg)
        self.chain(policy,'chat_shared_01',DOT,GUEST,4,'explicit-lower-hop')
        self.assertEqual(policy.hop_limit('chat_private_01'),100)


if __name__ == '__main__':
    unittest.main()
