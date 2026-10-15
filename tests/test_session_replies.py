"""Synthetic private-backend contract; no account enrollment or live credentials."""
import hashlib
import json
import threading
import time
import unittest
from types import SimpleNamespace
from urllib.request import Request, ProxyHandler, build_opener
from unittest.mock import patch

from babel.auth import Policy, ScopedStore
from babel.core import BridgeError, Store
from babel.gateway import Gateway
from babel.session_replies import EMBER, reply_routes

WORKER = 'bits255.codex.auto_0123456789abcdef0123456789abcdef'
OTHER = 'bits255.codex.auto_fedcba9876543210fedcba9876543210'
GUEST = 'guest.codex.auto_0123456789abcdef0123456789abcdef'
CID = 'report_auto_0123456789abcdef0123456789abcdef_ember'
TOKENS = {p: 'public-synthetic-reply-credential-'+str(n).zfill(12)
          for n, p in enumerate((EMBER, WORKER, OTHER, GUEST))}


class SessionReplyTests(unittest.TestCase):
    def setUp(self):
        now = time.time()
        participants = {}
        for pid, token in TOKENS.items():
            owner, client, session = pid.split('.')
            participants[pid] = dict(owner=owner, client=client, session=session,
                state='active', accepted=True, activated_at=int(now)-60, expires=None,
                sha256=hashlib.sha256(token.encode()).hexdigest())
        def conv(pid):
            return dict(state='active', participants=[pid, EMBER],
                routes=[dict(sender=pid, recipient=EMBER)], approval='automatic')
        self.cfg = dict(schema_version=3, owners={o: dict(enabled=True) for o in ('bits255', 'guest')},
            participants=participants, conversations={CID: conv(WORKER), 'other_incoming_01': conv(OTHER),
                                                     'guest_incoming_01': conv(GUEST)})
        self.policy = Policy(self.cfg)
        self.store = Store(':memory:')
        self.addCleanup(self.store.close)
        # These are the existing backend's internal interfaces, not public RPC.
        self.row = dict(participant=WORKER, conversation=CID, profile='ember_outbound',
                        state='active', generation=1, deadline=now+86400)
        def active(pid, generation=None):
            if pid != WORKER:
                return  # The backend does not own static sister/guest actors.
            if (self.row['state'] != 'active' or time.time() >= self.row['deadline']
                    or generation != self.row['generation']):
                raise BridgeError('Synthetic lease unavailable', 403)
        self.leases = SimpleNamespace(store=self.store,
            row=lambda pid: dict(self.row) if pid == WORKER else None, assert_active=active,
            project=lambda policy: policy, cleanup=lambda: 0, report_activity=lambda *args: None)
        self.store.sessions = self.leases
        self.policy.session_leases = self.leases
        self.policy.session_dynamic_roles = {WORKER}
        self.policy.session_generations = {WORKER: 1}
        self.store.policy_provider = lambda: self.policy

    def scope(self, role=EMBER, recipients=None):
        return ScopedStore(self.store, role, self.policy.agents[role][1] if recipients is None else recipients, self.policy)

    def incoming(self, mid='incoming-question-01', provenance='mcp', source=WORKER, cid=CID):
        return self.scope(source).stage(source, EMBER, text='Question?', message_id=mid,
            conversation_id=cid, provenance=provenance)['message']

    def reply(self, parent='incoming-question-01', mid='outgoing-reply-0001', scope=None):
        return (scope or self.scope()).stage(EMBER, WORKER, text='Approved answer.',
            message_id=mid, reply_to=parent, conversation_id=CID, provenance='mcp')

    def contacts(self, role=EMBER):
        return self.scope(role).contacts(role)

    def test_approved_acknowledged_parent_discovery_reply_and_dedup(self):
        ember = self.scope()
        self.assertFalse(self.contacts())
        parent = self.incoming()
        self.assertEqual(self.contacts(), [dict(recipient=WORKER, conversation_id=CID)])
        ember.claim_message(parent['id'], EMBER, 'reply-claim-0001')
        ember.acknowledge(parent['id'], EMBER, 'reply-claim-0001')
        row = self.reply(scope=ember)['message']
        self.assertEqual((row['status'], row['provenance'], row['hops']), ('queued', 'mcp', 2))
        self.assertEqual((row['source_owner'], row['recipient_owner'], row['root_id']), ('bits255', 'bits255', parent['id']))
        self.assertEqual([m['id'] for m in self.scope(WORKER).inbox(WORKER)], [row['id']])
        self.assertTrue(self.reply(scope=ember)['duplicate'])
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM events WHERE message_id=? AND action='approved'", (row['id'],)).fetchone()[0], 1)
        with self.assertRaises(BridgeError):
            ember.stage(EMBER, WORKER, text='Changed.', message_id=row['id'], reply_to=parent['id'], conversation_id=CID)

    def test_no_backend_or_dynamic_inventory_does_not_grant_by_auto_name(self):
        self.incoming()
        self.store.sessions = None
        self.assertFalse(self.contacts())
        self.store.sessions = self.leases
        self.policy.session_dynamic_roles = set()
        self.assertFalse(self.contacts())

    def test_unrelated_and_cross_owner_senders_do_not_get_return_grants(self):
        parent = self.incoming()
        self.incoming('guest-question-01', source=GUEST, cid='guest_incoming_01')
        self.incoming('other-question-01', source=OTHER, cid='other_incoming_01')
        # Even a backend inventory entry cannot cross the pinned owner boundary.
        self.policy.session_dynamic_roles.add(GUEST)
        self.policy.session_generations[GUEST] = 1
        self.leases.row = lambda pid: (dict(self.row) if pid == WORKER else
            dict(self.row, participant=GUEST, conversation='guest_incoming_01') if pid == GUEST else None)
        self.assertEqual(self.contacts(), [dict(recipient=WORKER, conversation_id=CID)])
        for role in (OTHER, GUEST):
            self.assertNotIn(dict(recipient=WORKER, conversation_id=CID), self.contacts(role))
            with self.assertRaises(BridgeError):
                self.scope(role).stage(role, WORKER, text='No access.', message_id='unrelated-reply-01',
                    reply_to=parent['id'], conversation_id=CID)
            with self.assertRaises(BridgeError):
                self.scope(role).message_status(parent['id'], role)
        with self.assertRaises(BridgeError):
            self.scope().stage(EMBER, GUEST, text='No implicit cross-owner access.', message_id='guest-reply-0001',
                reply_to='guest-question-01', conversation_id='guest_incoming_01')

    def test_captured_scope_cannot_expand_for_regular_explicit_routes(self):
        # A deliberate captured restriction still applies to the existing forward grant.
        with self.assertRaises(BridgeError):
            self.scope(WORKER, ()).stage(WORKER, EMBER, text='Outside scope.', message_id='scope-denied-001', conversation_id=CID)
        self.incoming()
        self.assertEqual(self.reply(scope=self.scope(EMBER, ()))['message']['status'], 'queued')

    def test_direct_core_send_requires_parent_and_mcp_provenance(self):
        self.incoming()
        for parent in (None, ''):
            with self.subTest(parent=parent), self.assertRaises(BridgeError):
                self.reply(parent)
        with self.assertRaises(BridgeError):
            self.store.stage(EMBER, WORKER, text='No root instructions.', message_id='raw-no-parent-01',
                conversation_id=CID, policy=self.policy)
        manual = self.incoming('manual-parent-01', provenance='manual')
        with self.assertRaises(BridgeError):
            self.store.stage(EMBER, WORKER, text='Manual parent is insufficient.', message_id='raw-manual-0001',
                conversation_id=CID, reply_to=manual['id'], policy=self.policy)

    def test_draft_cancelled_and_manual_messages_do_not_discover_contacts(self):
        parent = self.incoming(provenance='manual')
        self.assertFalse(self.contacts())
        for status in ('draft', 'canceled'):
            self.store.db.execute("UPDATE messages SET status=?,provenance='mcp' WHERE id=?", (status, parent['id']))
            self.store.db.commit()
            self.assertFalse(self.contacts())
            with self.assertRaises(BridgeError):
                self.reply(parent['id'])

    def test_forged_owner_binding_neither_discovers_nor_authorizes(self):
        parent = self.incoming()
        self.store.db.execute("UPDATE messages SET source_owner='guest' WHERE id=?", (parent['id'],))
        self.store.db.commit()
        self.assertFalse(self.contacts())
        self.incoming('valid-parent-0001')
        with self.assertRaises(BridgeError):
            self.reply(parent['id'])
        with self.assertRaises(BridgeError):
            self.store.stage(EMBER, WORKER, text='Forged parent.', message_id='raw-forged-0001',
                reply_to=parent['id'], conversation_id=CID, policy=self.policy)

    def test_wrong_conversation_route_and_unapproved_parents_rejected(self):
        self.incoming()
        invalid = ['missing-parent-01', self.reply()['message']['id']]
        for status in ('draft', 'canceled'):
            row = self.incoming('parent-'+status+'-0001')
            self.store.db.execute('UPDATE messages SET status=? WHERE id=?', (status, row['id']))
            self.store.db.commit()
            invalid.append(row['id'])
        invalid.append(self.incoming('other-parent-0001', source=OTHER, cid='other_incoming_01')['id'])
        for parent in invalid:
            with self.subTest(parent=parent), self.assertRaises(BridgeError):
                self.reply(parent, 'invalid-reply-0001')

    def test_expiry_revocation_generation_and_disabled_backend_block_cached_scope(self):
        self.incoming()
        ember = self.scope()
        for change in ({'deadline': time.time()}, {'state': 'revoked'}, {'generation': 2}, {'profile': 'existing_grants'}):
            before = dict(self.row)
            self.row.update(change)
            with self.subTest(change=change):
                self.assertFalse(ember.contacts(EMBER))
                with self.assertRaises(BridgeError):
                    self.reply(scope=ember)
            self.row.update(before)
        self.store.sessions = None
        with self.assertRaises(BridgeError):
            self.reply(scope=ember)

    def test_owner_disable_and_forward_grant_removal_deny_return_access(self):
        self.incoming()
        self.policy.owners['bits255']['enabled'] = False
        self.assertFalse(reply_routes(self.policy))
        self.policy.owners['bits255']['enabled'] = True
        self.policy.routes = frozenset()
        self.assertFalse(self.contacts())

    def test_approval_mode_fingerprints_and_lifetimes_are_preserved(self):
        before = (dict(self.policy.agents), dict(self.row))
        self.incoming()
        self.policy.conversations[CID]['approval'] = 'manual'
        result = self.reply()
        self.assertEqual(result['message']['status'], 'draft')
        self.store.approve(result['message']['id'])
        self.assertEqual(before, (dict(self.policy.agents), dict(self.row)))
        self.assertEqual(self.policy.routes, Policy(self.cfg).routes)

    def test_hop_sender_owner_rate_limits_and_duplicate_retries(self):
        self.incoming()
        with patch('babel.core.OWNER_RATE_LIMIT', 1):
            with self.assertRaises(BridgeError) as denied:
                self.reply()
            self.assertEqual(denied.exception.status, 429)
        with patch('babel.auth.MAX_HOPS', 2), patch('babel.core.RATE_LIMIT', 1):
            row = self.reply()['message']
            self.assertTrue(self.reply()['duplicate'])
            with self.assertRaises(BridgeError) as denied:
                self.reply(mid='rate-denied-0001')
            self.assertEqual(denied.exception.status, 429)
            with self.assertRaises(BridgeError) as denied:
                self.scope(WORKER).stage(WORKER, EMBER, text='Too many hops.', message_id='hop-denied-0001',
                    reply_to=row['id'], conversation_id=CID)
            self.assertEqual(denied.exception.status, 409)

    def test_authenticated_http_round_trip_after_acknowledgment(self):
        gateway = Gateway(0, self.policy, 'https://babel.example.test', store=self.store)
        thread = threading.Thread(target=gateway.serve_forever, daemon=True)
        thread.start()
        try:
            opener = build_opener(ProxyHandler({}))
            def call(role, name, **arguments):
                data = dict(jsonrpc='2.0', id=1, method='tools/call', params=dict(name=name, arguments=arguments))
                req = Request('http://127.0.0.1:'+str(gateway.port)+'/mcp/v1', data=json.dumps(data).encode(),
                    headers={'Host': 'babel.example.test', 'X-Forwarded-Proto': 'https', 'Authorization': 'Bearer '+TOKENS[role],
                             'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'})
                with opener.open(req, timeout=3) as response:
                    result = json.load(response)['result']
                self.assertFalse(result.get('isError'), result)
                return json.loads(result['content'][0]['text'])
            self.assertFalse(call(EMBER, 'list_contacts')['contacts'])
            parent = call(WORKER, 'stage_message', recipient=EMBER, conversation_id=CID,
                message_id='http-question-0001', text='Question?')['message']
            call(EMBER, 'claim_message', message_id=parent['id'], claim_id='http-claim-0001')
            call(EMBER, 'acknowledge_message', message_id=parent['id'], claim_id='http-claim-0001')
            self.assertEqual(call(EMBER, 'list_contacts')['contacts'], [dict(recipient=WORKER, conversation_id=CID)])
            reply = call(EMBER, 'stage_message', recipient=WORKER, conversation_id=CID, reply_to=parent['id'],
                message_id='http-reply-000001', text='Approved answer.')['message']
            self.assertEqual([m['id'] for m in call(WORKER, 'receive_messages')['messages']], [reply['id']])
        finally:
            gateway.shutdown()
            gateway.server_close()
            thread.join(timeout=3)
