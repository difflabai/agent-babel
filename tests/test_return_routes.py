"""Synthetic identities, in-memory/private temporary DBs; no production calls."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request, build_opener, ProxyHandler
from babel.auth import Policy, ScopedStore
from babel.core import Store, BridgeError
from babel.gateway import Gateway
from babel.mcp import TOOLS
from babel.session_leases import SessionLeases, EMBER, IDLE_SECONDS
from tests.test_session_leases import fixture, accounts, sha, TOKENS, SID, FORK, ADA, MANUAL

PEER = 'mikkel@pop-os'


class ReturnRouteTests(unittest.TestCase):
    def setUp(self):
        self.now = time.time()
        self.clock = patch('time.time', side_effect=lambda: self.now)
        self.clock.start()
        self.cfg = fixture(self.now)
        self.base = Policy(self.cfg)
        self.store = Store(':memory:')
        self.leases = SessionLeases(self.store, accounts(), clock=lambda: self.now)
        self.store.sync_policy(self.base)
        self.mailbox = self.boot()

    def tearDown(self):
        self.store.close()
        self.clock.stop()

    def boot(self, sid=SID, token='auto', peer=PEER, client='codex'):
        return self.leases.bootstrap(self.base, peer=peer, client=client,
            native_id=sid, sha256=sha(TOKENS[token]), event_id='synthetic-bootstrap-'+sid)

    def policy(self):
        return self.store.authorized_policy(self.base)

    def scoped(self, participant):
        policy = self.policy()
        return ScopedStore(self.store, participant, policy.agents[participant][1], policy)

    def decide(self, **overrides):
        options = dict(action='grant', operation_id='operator-grant-0001', sender=EMBER,
            recipient=self.mailbox['participant'], conversation=self.mailbox['conversation'],
            peer=PEER, native_id=SID)
        options.update(overrides)
        if options['action']=='revoke':
            options.setdefault('grant_operation_id','operator-grant-0001')
        return self.store.return_routes.decide(None if options['action']=='revoke' else self.policy(), **options)

    def test_explicit_grant_round_trip_claim_ack_and_no_unrelated_permissions(self):
        other = self.boot(FORK, 'fork')
        before = copy.deepcopy(self.cfg)
        source = self.mailbox['participant']; cid = self.mailbox['conversation']
        with self.assertRaises(BridgeError): self.policy().assert_route(cid, EMBER, source)
        outgoing = self.scoped(source).stage(source, EMBER, message_id='synthetic-intro-0001',
            text='Selected synthetic introduction for a return-route test.', conversation_id=cid, provenance='mcp')['message']
        self.scoped(EMBER).claim_message(outgoing['id'], EMBER, 'synthetic-claim-intro')
        self.scoped(EMBER).acknowledge(outgoing['id'], EMBER, 'synthetic-claim-intro')
        lease_before = self.leases.row(source)
        credentials_before = [dict(r) for r in self.store.db.execute('SELECT * FROM credential_bindings ORDER BY digest')]
        subscriptions_before = [dict(r) for r in self.store.db.execute('SELECT * FROM subscriptions')]
        self.assertTrue(self.decide()['changed'])
        p = self.policy()
        self.assertIn({'recipient':source, 'conversation_id':cid}, self.scoped(EMBER).contacts(EMBER))
        with self.assertRaises(BridgeError): p.assert_route(other['conversation'], EMBER, other['participant'])
        with self.assertRaises(BridgeError): p.assert_route(cid, ADA, source)
        reply = self.scoped(EMBER).stage(EMBER, source, message_id='synthetic-reply-0001',
            text='Selected synthetic return instruction.', reply_to=outgoing['id'], conversation_id=cid, provenance='mcp')['message']
        self.assertEqual(reply['status'], 'queued')
        self.assertEqual(self.scoped(source).claim_message(reply['id'], source, 'synthetic-claim-reply')['message']['source'], EMBER)
        self.scoped(source).acknowledge(reply['id'], source, 'synthetic-claim-reply')
        self.assertEqual(self.leases.row(source), lease_before)
        self.assertEqual(self.cfg, before)
        self.assertEqual([dict(r) for r in self.store.db.execute('SELECT * FROM credential_bindings ORDER BY digest')], credentials_before)
        self.assertEqual([dict(r) for r in self.store.db.execute('SELECT * FROM subscriptions')], subscriptions_before)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM return_route_decisions').fetchone()[0], 1)

    def test_exact_session_owner_conversation_generation_and_sender_scope(self):
        for change in ({'peer':'work@pop-os'}, {'native_id':FORK}, {'conversation':'manual_ember_chat'},
                       {'sender':ADA}, {'recipient':MANUAL}, {'expected_generation':99}):
            with self.subTest(change=change), self.assertRaises(BridgeError): self.decide(**change)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM return_route_decisions').fetchone()[0], 0)

    def test_grant_rejects_expired_closed_revoked_disabled_and_static_collision(self):
        self.now = self.mailbox['deadline']
        with self.assertRaises(BridgeError): self.decide()
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM return_route_decisions').fetchone()[0], 0)
        # Fresh fixtures keep independent failure reasons reviewable.
        for state in ('closed','revoked'):
            with self.subTest(state=state):
                cfg = copy.deepcopy(self.cfg); cfg['participants'][EMBER]['state'] = state
                with self.assertRaises(BridgeError): self.store.return_routes.decide(Policy(cfg), action='grant',
                    operation_id='reject-'+state, sender=EMBER, recipient=MANUAL, conversation='manual_ember_chat')

    def test_dry_run_retry_revoke_and_audit_id_conflict(self):
        original = self.leases.row(self.mailbox['participant'])
        self.assertFalse(self.decide(dry_run=True)['changed'])
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM return_route_decisions').fetchone()[0], 0)
        grant = self.decide()
        self.now += 100
        self.assertFalse(self.decide()['changed'])
        with self.assertRaises(BridgeError): self.decide(action='revoke')
        self.decide(action='revoke', operation_id='operator-revoke-0001')
        self.decide()  # Old retry cannot restore a later revoked decision.
        with self.assertRaises(BridgeError): self.policy().assert_route(self.mailbox['conversation'], EMBER, self.mailbox['participant'])
        self.assertEqual(self.leases.row(self.mailbox['participant']), original)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM return_route_decisions').fetchone()[0], 1)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM return_route_withdrawals').fetchone()[0], 1)
        self.assertEqual(grant['expires'], original['deadline'])

    def test_grant_never_extends_to_renewed_lease_or_new_credential_generation(self):
        grant = self.decide()
        cached = self.policy(); source = self.mailbox['participant']; cid = self.mailbox['conversation']
        self.now += 100
        self.leases.bootstrap(self.base, peer=PEER, client='codex', native_id=SID,
            sha256=sha(TOKENS['auto']), kind='turn', event_id='synthetic-native-turn-0001')
        self.assertGreater(self.leases.row(source)['deadline'], grant['expires'])
        self.now = grant['expires']
        with self.assertRaises(BridgeError): cached.assert_route(cid, EMBER, source)
        with self.assertRaises(BridgeError): self.policy().assert_route(cid, EMBER, source)
        self.decide(operation_id='operator-grant-0002')
        self.leases.bootstrap(self.base, peer=PEER, client='codex', native_id=SID,
            sha256=sha(TOKENS['rotated']), kind='resume', event_id='synthetic-native-resume-0001')
        with self.assertRaises(BridgeError): self.policy().assert_route(cid, EMBER, source)

    def test_cached_route_fails_closed_after_revoke_or_reprojection(self):
        self.decide(); cached = self.policy()
        self.assertEqual(self.store.authorized_policy(cached).routes, cached.routes)
        self.decide(action='revoke', operation_id='operator-revoke-0001')
        with self.assertRaises(BridgeError): cached.assert_route(self.mailbox['conversation'], EMBER, self.mailbox['participant'])
        self.leases.revoke(participant=self.mailbox['participant'])
        with self.assertRaises(BridgeError): self.decide(operation_id='operator-grant-0002')

    def test_route_and_audit_capacity_fail_without_permission_change(self):
        for constant, limit in (('MAX_ROUTES', len(self.policy().routes)), ('MAX_DECISIONS',0)):
            with self.subTest(constant=constant), patch('babel.return_routes.'+constant, limit), self.assertRaises(BridgeError): self.decide()
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM return_route_decisions').fetchone()[0], 0)

    def add_static(self, client, owner='bits255'):
        cfg = copy.deepcopy(self.cfg); pid = owner+'.'+client+'.synthetic_guest'
        cfg['owners'][owner] = {'enabled':True}
        cfg['participants'][pid] = dict(owner=owner, client=client, session='synthetic_guest', state='active',
            accepted=True, activated_at=int(self.now)-60, expires=None, sha256=sha('synthetic-private-fixture-'+client+'-'+owner))
        cid = 'synthetic_'+client+'_return'
        cfg['conversations'][cid] = dict(state='active', participants=[pid,EMBER], routes=[{'sender':pid,'recipient':EMBER}])
        return cfg, pid, cid

    def test_every_existing_authenticated_client_including_grok_static_lifecycle(self):
        for client in ('codex','claude','cursor','opencode','grokbot','dots','muse'):
            with self.subTest(client=client):
                cfg, pid, cid = self.add_static(client); base = Policy(cfg)
                result = self.store.return_routes.decide(base, action='grant', operation_id='synthetic-static-'+client,
                    sender=EMBER, recipient=pid, conversation=cid)
                self.assertIsNone(result['generation']); self.assertIsNone(result['expires'])
                p = self.store.authorized_policy(base); p.assert_route(cid, EMBER, pid)
                cfg['participants'][pid]['state'] = 'closed'
                with self.assertRaises(BridgeError): self.store.authorized_policy(Policy(cfg)).assert_route(cid, EMBER, pid)

    def test_existing_leased_grok_and_opencode_keep_lease_and_original_grants(self):
        for client in ('grokbot','opencode'):
            with self.subTest(client=client):
                cfg, pid, cid = self.add_static(client); base = Policy(cfg)
                config = accounts()
                config['accounts'][PEER]['clients'].append(client)
                leases = SessionLeases(self.store, config, clock=lambda:self.now)
                self.store.sync_policy(base)
                native = 'legacy:synthetic-'+client
                leases.adopt(base, peer=PEER, participant=pid, native_id=native, evidence='rollout_grace')
                before = leases.row(pid)
                result = self.store.return_routes.decide(self.store.authorized_policy(base), action='grant',
                    operation_id='synthetic-leased-'+client, sender=EMBER, recipient=pid, conversation=cid,
                    peer=PEER, native_id=native)
                self.assertEqual(result['generation'], before['generation']); self.assertEqual(result['expires'], before['deadline'])
                self.store.authorized_policy(base).assert_route(cid, EMBER, pid)
                self.assertEqual(leases.row(pid), before)
                self.now = before['deadline']
                with self.assertRaises(BridgeError): self.store.authorized_policy(base).assert_route(cid, EMBER, pid)

    def test_cross_owner_and_unowned_native_context_rejected(self):
        cfg, pid, cid = self.add_static('grokbot', owner='otherowner')
        with self.assertRaises(BridgeError): self.store.return_routes.decide(Policy(cfg), action='grant',
            operation_id='synthetic-crossowner', sender=EMBER, recipient=pid, conversation=cid)
        cfg, pid, cid = self.add_static('grokbot')
        with self.assertRaises(BridgeError): self.store.return_routes.decide(Policy(cfg), action='grant',
            operation_id='synthetic-falsecontext', sender=EMBER, recipient=pid, conversation=cid, peer=PEER, native_id=SID)

    def test_static_collision_and_disabled_lifecycle_fail_closed(self):
        self.decide(); source=self.mailbox['participant']; cid=self.mailbox['conversation']
        projected=self.leases.project(self.base)
        cfg=copy.deepcopy(self.cfg); cfg['participants'][source]=projected.participants[source]
        with self.assertRaises(BridgeError): self.store.authorized_policy(Policy(cfg))
        self.store.sessions=None
        with self.assertRaises(BridgeError): self.store.authorized_policy(self.base).assert_route(cid,EMBER,source)

    def test_automatic_claude_and_cursor_do_not_require_codex_label(self):
        for client, token in (('claude','fork'),('cursor','rotated')):
            with self.subTest(client=client):
                mailbox=self.boot(FORK,token,client=client)
                self.decide(operation_id='operator-grant-'+client, recipient=mailbox['participant'],
                    conversation=mailbox['conversation'], native_id=FORK)
                self.policy().assert_route(mailbox['conversation'],EMBER,mailbox['participant'])

    def test_static_owner_expiry_and_public_tool_boundary(self):
        cfg,pid,cid=self.add_static('grokbot'); base=Policy(cfg)
        self.store.return_routes.decide(base,action='grant',operation_id='static-lifecycle-grant',sender=EMBER,recipient=pid,conversation=cid)
        cfg['owners']['bits255']['enabled']=False
        with self.assertRaises(BridgeError): self.store.authorized_policy(Policy(cfg)).assert_route(cid,EMBER,pid)
        cfg['owners']['bits255']['enabled']=True
        cfg['participants'][pid]['expires']=int(self.now)+1
        self.now+=2
        with self.assertRaises(BridgeError): self.store.authorized_policy(Policy(cfg)).assert_route(cid,EMBER,pid)
        self.assertFalse(any('return-route' in t['name'] or 'grant' in t['name'] for t in TOOLS))

    def test_missing_outgoing_route_or_revoked_account_cannot_grant(self):
        cfg=copy.deepcopy(self.cfg);cfg['conversations']['manual_ember_chat']['routes']=[]
        with self.assertRaises(BridgeError): self.store.return_routes.decide(Policy(cfg),action='grant',
            operation_id='no-outgoing-grant',sender=EMBER,recipient=MANUAL,conversation='manual_ember_chat')
        self.leases.revoke(peer=PEER)
        with self.assertRaises(BridgeError): self.decide()

    def test_revoke_at_actual_audit_saturation_preserves_bounded_immutable_logs(self):
        grant=self.decide()
        fields=('operation_id','action','conversation','sender','recipient','owner','peer','native_id','generation','expires','created')
        values=tuple(grant[k] for k in fields)
        with self.store.transaction():
            self.store.db.executemany('INSERT INTO return_route_decisions('+','.join(fields)+') VALUES('+','.join('?' for _ in fields)+')',
                [('saturated-grant-'+str(i).zfill(5),)+values[1:] for i in range(8191)])
        latest='saturated-grant-08190'
        before=[tuple(r) for r in self.store.db.execute('SELECT * FROM return_route_decisions ORDER BY seq')]
        with self.assertRaises(BridgeError):self.decide(operation_id='capacity-denied-grant')
        result=self.decide(action='revoke',operation_id='capacity-permitted-withdrawal',grant_operation_id=latest)
        self.assertTrue(result['withdrawn'])
        self.assertEqual([tuple(r) for r in self.store.db.execute('SELECT * FROM return_route_decisions ORDER BY seq')],before)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM return_route_withdrawals').fetchone()[0],1)
        with self.assertRaises(BridgeError):self.policy().assert_route(self.mailbox['conversation'],EMBER,self.mailbox['participant'])
        self.assertFalse(self.decide(action='revoke',operation_id='capacity-permitted-withdrawal',grant_operation_id=latest)['changed'])
        with self.assertRaises(BridgeError):self.decide(action='revoke',operation_id='no-unbounded-extra-audit',grant_operation_id=latest)

    def test_revoke_after_static_grok_policy_removal_cannot_resurface(self):
        cfg,pid,cid=self.add_static('grokbot');base=Policy(cfg)
        args=dict(sender=EMBER,recipient=pid,conversation=cid)
        self.store.return_routes.decide(base,action='grant',operation_id='grok-original-grant',**args)
        removed=copy.deepcopy(cfg);removed['conversations'][cid]['routes']=[]
        self.assertNotIn((cid,EMBER,pid),self.store.authorized_policy(Policy(removed)).routes)
        self.store.return_routes.decide(None,action='revoke',operation_id='grok-stored-withdrawal',grant_operation_id='grok-original-grant',**args)
        restored=self.store.authorized_policy(Policy(cfg))
        with self.assertRaises(BridgeError):restored.assert_route(cid,EMBER,pid)
        # Even removal of the whole live identity/policy does not impede withdrawal.
        self.assertFalse(self.store.return_routes.decide(None,action='revoke',operation_id='grok-stored-withdrawal',grant_operation_id='grok-original-grant',**args)['changed'])

    def test_withdrawal_of_expired_rotated_or_disabled_lease_uses_original_scope(self):
        self.decide();source=self.mailbox['participant']
        self.leases.bootstrap(self.base,peer=PEER,client='codex',native_id=SID,sha256=sha(TOKENS['rotated']),kind='resume',event_id='withdrawal-rotation-event')
        before=self.leases.row(source)
        self.now=before['deadline']
        self.store.sessions=None
        result=self.decide(action='revoke',operation_id='withdraw-old-generation',expected_generation=1)
        self.assertTrue(result['withdrawn']);self.assertEqual(result['generation'],1)
        self.assertEqual(self.leases.row(source),before)
        self.assertFalse(self.decide(action='revoke',operation_id='withdraw-old-generation',expected_generation=1)['changed'])
        with self.assertRaises(BridgeError):self.decide(action='revoke',operation_id='wrong-generation-withdrawal',expected_generation=2)

    def test_withdrawal_exact_scope_and_global_operation_id_conflicts(self):
        self.decide()
        for args in ({'peer':'work@pop-os'},{'native_id':FORK},{'sender':ADA},{'conversation':'manual_ember_chat'},
                     {'grant_operation_id':'nonexistent-grant'},{'expected_generation':99}):
            with self.subTest(args=args),self.assertRaises(BridgeError):self.decide(action='revoke',operation_id='reject-wrong-withdrawal',**args)
        self.decide(action='revoke',operation_id='scoped-withdrawal')
        with self.assertRaises(BridgeError):self.decide(operation_id='scoped-withdrawal')
        with self.assertRaises(BridgeError):self.decide(action='revoke',operation_id='operator-grant-0001')
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM return_route_withdrawals').fetchone()[0],1)

    def test_old_withdrawal_retry_does_not_revoke_a_new_explicit_grant(self):
        self.decide();self.decide(action='revoke',operation_id='old-withdrawal')
        self.decide(operation_id='new-explicit-grant')
        self.decide(action='revoke',operation_id='old-withdrawal')
        self.policy().assert_route(self.mailbox['conversation'],EMBER,self.mailbox['participant'])
        with self.assertRaises(BridgeError):self.decide(action='revoke',operation_id='old-withdrawal',grant_operation_id='new-explicit-grant')
        self.decide(action='revoke',operation_id='new-explicit-withdrawal',grant_operation_id='new-explicit-grant')
        with self.assertRaises(BridgeError):self.policy().assert_route(self.mailbox['conversation'],EMBER,self.mailbox['participant'])


class OperatorCLITests(unittest.TestCase):
    def test_cli_withdrawal_survives_missing_policy_and_accounts_and_rotated_expired_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);db=root/'bridge.sqlite3';cfg=fixture(time.time());base=Policy(cfg)
            store=Store(db);leases=SessionLeases(store,accounts())
            mailbox=leases.bootstrap(base,peer=PEER,client='codex',native_id=SID,sha256=sha(TOKENS['auto']),event_id='missing-policy-start')
            scope=dict(sender=EMBER,recipient=mailbox['participant'],conversation=mailbox['conversation'],peer=PEER,native_id=SID)
            store.return_routes.decide(store.authorized_policy(base),action='grant',operation_id='missing-policy-grant',**scope)
            with store.transaction():
                store.db.execute("UPDATE trusted_sessions SET state='idle_expired',generation=2 WHERE participant=?",(mailbox['participant'],))
            original=store.trusted_session_row(mailbox['participant']);store.close()
            cmd=[sys.executable,'-m','babel','return-route','--database-file',str(db),
                '--policy-file',str(root/'missing-policy.json'),'--accounts-file',str(root/'missing-accounts.json'),
                '--action','revoke','--operation-id','missing-policy-withdrawal','--grant-operation-id','missing-policy-grant',
                '--sender',EMBER,'--recipient',mailbox['participant'],'--conversation',mailbox['conversation'],
                '--peer',PEER,'--native-id',SID,'--expected-generation','1']
            for flags,expected in ((['--dry-run'],0),([],1),([],1)):
                result=subprocess.run(cmd+flags,cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)
                payload=json.loads(result.stdout);self.assertEqual(payload['generation'],1)
                store=Store(db)
                self.assertEqual(store.trusted_session_row(mailbox['participant']),original)
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM return_route_withdrawals').fetchone()[0],expected)
                store.close()

    def test_concurrent_same_operation_id_cannot_be_both_grant_and_withdrawal(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'bridge.sqlite3';base=Policy(fixture(time.time()));args=dict(sender=EMBER,recipient=MANUAL,conversation='manual_ember_chat')
            initial=Store(db);initial.return_routes.decide(base,action='grant',operation_id='initial-race-grant',**args);initial.close()
            barrier=threading.Barrier(2);results=[];lock=threading.Lock()
            def compete(action):
                store=Store(db)
                try:
                    barrier.wait(timeout=5)
                    options=dict(action=action,operation_id='shared-race-operation',**args)
                    if action=='revoke':options['grant_operation_id']='initial-race-grant'
                    try:result=store.return_routes.decide(base if action=='grant' else None,**options)
                    except BridgeError as exc:result=exc.status
                    with lock:results.append((action,result))
                finally:store.close()
            threads=[threading.Thread(target=compete,args=(action,)) for action in ('grant','revoke')]
            for thread in threads:thread.start()
            for thread in threads:thread.join(timeout=10);self.assertFalse(thread.is_alive())
            self.assertEqual(len(results),2)
            self.assertEqual(sum(isinstance(result,dict) for _,result in results),1)
            self.assertEqual(sum(result==409 for _,result in results),1)
            store=Store(db)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM (SELECT operation_id FROM return_route_decisions UNION ALL SELECT operation_id FROM return_route_withdrawals) WHERE operation_id=?',('shared-race-operation',)).fetchone()[0],1)
            store.close()

    def test_concurrent_grant_retry_withdrawal_and_policy_reload_leave_durable_denial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);db=root/'bridge.sqlite3';file=root/'agents.json';cfg=fixture(time.time())
            pid='bits255.grokbot.concurrent_guest';cid='concurrent_grok_return'
            cfg['participants'][pid]=dict(owner='bits255',client='grokbot',session='concurrent_guest',state='active',
                accepted=True,activated_at=int(time.time())-60,expires=None,sha256=sha('synthetic-concurrent-grok-token'))
            cfg['conversations'][cid]=dict(state='active',participants=[pid,EMBER],routes=[{'sender':pid,'recipient':EMBER}])
            file.write_text(json.dumps(cfg));base=Policy.load(file);args=dict(sender=EMBER,recipient=pid,conversation=cid)
            store=Store(db);store.return_routes.decide(base,action='grant',operation_id='reload-original-grant',**args);store.close()
            removed=copy.deepcopy(cfg);removed['conversations'][cid]['routes']=[]
            barrier=threading.Barrier(3);withdrawn=threading.Event();failures=[];lock=threading.Lock()
            def record(exc):
                with lock:failures.append(repr(exc))
            def retry():
                store=Store(db)
                try:
                    barrier.wait(timeout=5)
                    for _ in range(10):store.return_routes.decide(base,action='grant',operation_id='reload-original-grant',**args)
                    self.assertTrue(withdrawn.wait(timeout=5))
                    self.assertFalse(store.return_routes.decide(base,action='grant',operation_id='reload-original-grant',**args)['changed'])
                except Exception as exc:record(exc)
                finally:store.close()
            def withdraw():
                store=Store(db)
                try:
                    barrier.wait(timeout=5)
                    store.return_routes.decide(None,action='revoke',operation_id='reload-withdrawal',grant_operation_id='reload-original-grant',**args)
                    withdrawn.set()
                except Exception as exc:record(exc)
                finally:store.close()
            def reload():
                store=Store(db)
                try:
                    barrier.wait(timeout=5)
                    for i in range(30):
                        replacement=file.with_suffix('.swap');replacement.write_text(json.dumps(cfg if i%2 else removed));replacement.replace(file)
                        if withdrawn.is_set():
                            policy=store.authorized_policy(Policy.load(file))
                            self.assertNotIn((cid,EMBER,pid),policy.routes)
                    file.write_text(json.dumps(cfg))
                except Exception as exc:record(exc)
                finally:store.close()
            threads=[threading.Thread(target=target) for target in (retry,withdraw,reload)]
            for thread in threads:thread.start()
            for thread in threads:thread.join(timeout=10);self.assertFalse(thread.is_alive())
            self.assertEqual(failures,[])
            store=Store(db)
            self.assertNotIn((cid,EMBER,pid),store.authorized_policy(Policy.load(file)).routes)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM return_route_decisions').fetchone()[0],1)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM return_route_withdrawals').fetchone()[0],1)
            store.close()

    def test_concurrent_new_grant_and_old_withdrawal_preserve_exact_decision_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'bridge.sqlite3';cfg=fixture(time.time())
            pid='bits255.grokbot.replacement_guest';cid='replacement_grok_return'
            cfg['participants'][pid]=dict(owner='bits255',client='grokbot',session='replacement_guest',state='active',
                accepted=True,activated_at=int(time.time())-60,expires=None,sha256=sha('synthetic-replacement-grok-token'))
            cfg['conversations'][cid]=dict(state='active',participants=[pid,EMBER],routes=[{'sender':pid,'recipient':EMBER}])
            base=Policy(cfg);args=dict(sender=EMBER,recipient=pid,conversation=cid)
            store=Store(db);store.return_routes.decide(base,action='grant',operation_id='race-old-grant',**args);store.close()
            barrier=threading.Barrier(2);failures=[];lock=threading.Lock()
            def operate(action):
                store=Store(db)
                try:
                    barrier.wait(timeout=5)
                    if action=='grant':store.return_routes.decide(base,action='grant',operation_id='race-new-grant',**args)
                    else:store.return_routes.decide(None,action='revoke',operation_id='race-old-withdrawal',grant_operation_id='race-old-grant',**args)
                except Exception as exc:
                    with lock:failures.append(repr(exc))
                finally:store.close()
            threads=[threading.Thread(target=operate,args=(action,)) for action in ('grant','revoke')]
            for thread in threads:thread.start()
            for thread in threads:thread.join(timeout=10);self.assertFalse(thread.is_alive())
            self.assertEqual(failures,[])
            store=Store(db)
            store.authorized_policy(base).assert_route(cid,EMBER,pid)
            retry=store.return_routes.decide(None,action='revoke',operation_id='race-old-withdrawal',grant_operation_id='race-old-grant',**args)
            self.assertFalse(retry['changed']);store.authorized_policy(base).assert_route(cid,EMBER,pid)
            store.return_routes.decide(None,action='revoke',operation_id='race-new-withdrawal',grant_operation_id='race-new-grant',**args)
            with self.assertRaises(BridgeError):store.authorized_policy(base).assert_route(cid,EMBER,pid)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM return_route_decisions').fetchone()[0],2)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM return_route_withdrawals').fetchone()[0],2)
            store.close()

    def test_cli_dry_run_grant_and_revoke_persist_only_audited_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); db=root/'bridge.sqlite3'; policy=root/'agents.json'; account=root/'accounts.json'
            cfg=fixture(time.time()); policy.write_text(json.dumps(cfg)); account.write_text(json.dumps(accounts())); account.chmod(0o600)
            original=policy.read_bytes()
            store=Store(db); leases=SessionLeases(store,accounts())
            mailbox=leases.bootstrap(Policy(cfg),peer=PEER,client='codex',native_id=SID,sha256=sha(TOKENS['auto']),event_id='synthetic-cli-start')
            original_lease=leases.row(mailbox['participant']); store.close()
            cmd=[sys.executable,'-m','babel','return-route','--database-file',str(db),'--policy-file',str(policy),
                 '--accounts-file',str(account),'--peer',PEER,'--native-id',SID,'--sender',EMBER,
                 '--recipient',mailbox['participant'],'--conversation',mailbox['conversation']]
            for flags, counts in ((['--action','grant','--operation-id','synthetic-cli-grant','--dry-run'],(0,0)),
                                  (['--action','grant','--operation-id','synthetic-cli-grant'],(1,0)),
                                  (['--action','revoke','--operation-id','synthetic-cli-revoke','--grant-operation-id','synthetic-cli-grant'],(1,1))):
                result=subprocess.run(cmd+flags,cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr); json.loads(result.stdout)
                self.assertEqual(policy.read_bytes(),original)
                store=Store(db)
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM return_route_decisions').fetchone()[0],counts[0])
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM return_route_withdrawals').fetchone()[0],counts[1])
                self.assertEqual(store.trusted_session_row(mailbox['participant']),original_lease)
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM messages').fetchone()[0],0)
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM subscriptions').fetchone()[0],0)
                store.close()

    def test_local_gateway_observes_separate_operator_grant_and_revoke_without_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'bridge.sqlite3';cfg=fixture(time.time());base=Policy(cfg)
            gateway_store=Store(db);leases=SessionLeases(gateway_store,accounts())
            mailbox=leases.bootstrap(base,peer=PEER,client='codex',native_id=SID,sha256=sha(TOKENS['auto']),event_id='synthetic-gateway-start')
            server=Gateway(0,base,'https://babel.example.test',store=gateway_store)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            opener=build_opener(ProxyHandler({}))
            def tool(token,name,args):
                request=Request('http://127.0.0.1:'+str(server.port)+'/mcp/v1',
                    data=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args}}).encode(),
                    headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream',
                             'Authorization':'Bearer '+token,'Host':'babel.example.test','X-Forwarded-Proto':'https'})
                with opener.open(request,timeout=3) as response:
                    result=json.load(response)['result']
                return result, json.loads(result['content'][0]['text'])
            try:
                result,contacts=tool(TOKENS[EMBER],'list_contacts',{})
                self.assertNotIn(mailbox['participant'],{c['recipient'] for c in contacts['contacts']})
                operator=Store(db);SessionLeases(operator,accounts())
                args=dict(sender=EMBER,recipient=mailbox['participant'],conversation=mailbox['conversation'],peer=PEER,native_id=SID)
                operator.return_routes.decide(operator.authorized_policy(base),action='grant',operation_id='gateway-operator-grant',**args)
                result,contacts=tool(TOKENS[EMBER],'list_contacts',{})
                self.assertIn({'recipient':mailbox['participant'],'conversation_id':mailbox['conversation']},contacts['contacts'])
                result,sent=tool(TOKENS[EMBER],'stage_message',dict(recipient=mailbox['participant'],conversation_id=mailbox['conversation'],message_id='gateway-selected-return',text='Selected synthetic operator return message.'))
                self.assertFalse(result['isError']);self.assertEqual(sent['message']['status'],'queued')
                result,received=tool(TOKENS['auto'],'receive_messages',{})
                self.assertEqual(received['messages'][0]['id'],'gateway-selected-return')
                operator.return_routes.decide(None,action='revoke',operation_id='gateway-operator-revoke',grant_operation_id='gateway-operator-grant',**args)
                result,contacts=tool(TOKENS[EMBER],'list_contacts',{})
                self.assertNotIn(mailbox['participant'],{c['recipient'] for c in contacts['contacts']})
                operator.close()
            finally:
                server.shutdown();server.server_close();thread.join();gateway_store.close()


if __name__=='__main__': unittest.main()
