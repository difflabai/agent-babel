"""Synthetic credentials/context only. No hosts, real tokens or native turns."""
import copy
import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from urllib.request import Request, build_opener, ProxyHandler
from urllib.error import HTTPError
from babel.auth import Policy, ScopedStore
from babel.core import Store, BridgeError
from babel.session_leases import SessionLeases, EMBER, IDLE_SECONDS
from babel.account_bootstrap import context, request
from babel.session_operator import apply
from babel.gateway import Gateway
from account_session_helper import Helper

ADA='bits255.grokbot.grok_20261002'
MANUAL='bits255.codex.manual_01'
SID='01a0efd7-0e4f-7c80-8b1c-489afa0113c4'
FORK='01a0efd7-0e4f-7c80-8b1c-489afa0113c5'
TOKENS={p:'public-synthetic-credential-'+str(i).zfill(12) for i,p in enumerate((EMBER,ADA,MANUAL,'auto','rotated','fork'))}
def sha(token):return hashlib.sha256(token.encode()).hexdigest()
def fixture(now):
    participants={}
    for p in (EMBER,ADA,MANUAL):
        owner,client,session=p.split('.')
        participants[p]={'owner':owner,'client':client,'session':session,'state':'active','accepted':True,
                         'activated_at':int(now)-60,'expires':None,'sha256':sha(TOKENS[p])}
    def conv(a,b):return {'state':'active','participants':[a,b],'routes':[{'sender':a,'recipient':b},{'sender':b,'recipient':a}], 'approval':'automatic'}
    return {'schema_version':3,'owners':{'bits255':{'enabled':True}},'participants':participants,
            'conversations':{'manual_ember_chat':conv(MANUAL,EMBER),'manual_ada_chat':conv(MANUAL,ADA)}}
def accounts(cap=4,records=32):return {'schema_version':1,'accounts':{p:{'enabled':True,'clients':['codex','claude','cursor']} for p in ('mikkel@pop-os','work@pop-os')},'max_active':cap,'max_records':records}

class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.now=time.time();self.clockpatch=patch('time.time',side_effect=lambda:self.now);self.clockpatch.start()
        self.cfg=fixture(self.now);self.base=Policy(self.cfg);self.store=Store(':memory:')
        self.store.sync_policy(self.base)
        self.leases=SessionLeases(self.store,accounts(),clock=lambda:self.now)
    def tearDown(self):self.store.close();self.clockpatch.stop()
    def boot(self,sid=SID,token='auto',event='startup-event-01',kind='bootstrap',peer='mikkel@pop-os'):
        return self.leases.bootstrap(self.base,peer=peer,client='codex',native_id=sid,sha256=sha(TOKENS[token]),event_id=event,kind=kind)
    def scoped(self,p):
        policy=self.leases.project(self.base);return ScopedStore(self.store,p,policy.agents[p][1],policy)
    def send(self,b,mid='auto-report-0001',text='Finished synthetic task and verified the requested output.'):
        return self.scoped(b['participant']).stage(b['participant'],EMBER,message_id=mid,text=text,conversation_id=b['conversation'],provenance='mcp')
    def test_new_profile_outbound_ember_only_and_existing_both_sisters_unchanged(self):
        b=self.boot();p=self.leases.project(self.base);self.store.sync_policy(p)
        self.assertEqual(p.authenticate('Bearer '+TOKENS['auto']),b['participant'])
        self.assertEqual(self.scoped(b['participant']).contacts(b['participant']),[{'recipient':EMBER,'conversation_id':b['conversation']}])
        self.assertEqual({c['recipient'] for c in self.scoped(MANUAL).contacts(MANUAL)},{EMBER,ADA})
        self.assertEqual(p.participants[ADA],self.base.participants[ADA])
        with self.assertRaises(BridgeError):p.assert_route(b['conversation'],EMBER,b['participant'])
        with self.assertRaises(BridgeError):p.assert_route(b['conversation'],b['participant'],ADA)
        self.assertEqual(self.send(b)['message']['status'],'queued')
        self.assertEqual(self.cfg,fixture(self.now))
    def test_reconnect_deduplicates_without_extending_idle_time(self):
        b=self.boot();self.now+=3600;second=self.boot(event='different-bootstrap-02')
        self.assertEqual(b,second);self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM trusted_sessions').fetchone()[0],1)
    def test_fork_and_second_account_get_distinct_identities(self):
        a=self.boot();b=self.boot(FORK,'fork');c=self.boot(SID,'rotated',peer='work@pop-os')
        self.assertEqual(len({v['participant'] for v in (a,b,c)}),3)
        with self.assertRaises(BridgeError):self.boot(FORK,'auto')
    def test_exact_24h_boundary_and_no_poll_renewal(self):
        b=self.boot();self.now=b['deadline']-1
        for _ in range(3):
            s=self.scoped(b['participant']);s.contacts(b['participant']);s.inbox(b['participant']);s.history(b['participant'])
        self.assertEqual(self.leases.row(b['participant'])['deadline'],b['deadline'])
        self.now=b['deadline'];p=self.leases.project(self.base)
        with self.assertRaises(BridgeError):p.authenticate('Bearer '+TOKENS['auto'])
        self.assertEqual(self.leases.row(b['participant'])['state'],'idle_expired')
        self.assertEqual(self.scoped(EMBER).contacts(EMBER),[{'recipient':MANUAL,'conversation_id':'manual_ember_chat'}])
    def test_report_renewal_server_time_and_retry_is_not_activity(self):
        b=self.boot();self.now+=600;result=self.send(b);deadline=self.now+IDLE_SECONDS
        self.assertEqual(self.leases.row(b['participant'])['deadline'],deadline)
        self.now+=600;retry=self.send(b)
        self.assertTrue(retry['duplicate']);self.assertEqual(self.leases.row(b['participant'])['deadline'],deadline)
        self.scoped(b['participant']).message_status(result['message']['id'],b['participant'])
        self.assertEqual(self.leases.row(b['participant'])['deadline'],deadline)
    def test_empty_keepalive_and_idle_reads_never_renew(self):
        b=self.boot();self.now+=600
        for n,text in enumerate(('ping','heartbeat','keepalive','active','heartbeat!!!!!!!')):
            self.send(b,mid='keepalive-message-'+str(n),text=text)
        self.assertEqual(self.leases.row(b['participant'])['deadline'],b['deadline'])
    def test_real_turn_evidence_renews_but_dedup_and_timestamps_are_rejected(self):
        b=self.boot();self.now+=600;a=self.boot(event='native-turn-0001',kind='turn')
        self.assertEqual(a['deadline'],self.now+IDLE_SECONDS)
        self.now+=600;self.assertEqual(self.boot(event='native-turn-0001',kind='turn'),a)
        req=request('codex',sha(TOKENS['auto']),env={'CODEX_THREAD_ID':SID});req['timestamp']=self.now+999999
        with self.assertRaises(BridgeError):apply(self.store,accounts(),self.base,'mikkel@pop-os',req)
        req.pop('timestamp');req['kind']='heartbeat'
        with self.assertRaises(BridgeError):apply(self.store,accounts(),self.base,'mikkel@pop-os',req)
    def test_idle_resume_needs_fresh_evidence_rotates_fences_old_scope(self):
        b=self.boot();scope=self.scoped(b['participant']);self.send(b)
        self.now=b['deadline'];self.leases.cleanup()
        for kw in ({},{'kind':'resume','event':'startup-event-01'},{'kind':'resume','event':'resume-event-0001'}):
            with self.assertRaises(BridgeError):self.boot(**kw)
        resumed=self.boot(token='rotated',kind='resume',event='resume-event-0001')
        self.assertEqual(resumed['participant'],b['participant']);self.assertEqual(resumed['conversation'],b['conversation'])
        p=self.leases.project(self.base)
        with self.assertRaises(BridgeError):p.authenticate('Bearer '+TOKENS['auto'])
        self.assertEqual(p.authenticate('Bearer '+TOKENS['rotated']),b['participant'])
        with self.assertRaises(BridgeError):scope.contacts(b['participant'])
        self.assertEqual(len(self.scoped(b['participant']).history(b['participant'])),1)
        self.now+=100;self.assertEqual(self.boot(token='rotated',kind='resume',event='resume-event-0001'),resumed)
    def test_revoked_session_and_account_never_auto_reopen(self):
        b=self.boot();self.leases.revoke(participant=b['participant'])
        with self.assertRaises(BridgeError):self.boot(token='rotated',kind='resume',event='real-resume-event1')
        self.leases.revoke(peer='mikkel@pop-os')
        self.leases=SessionLeases(self.store,accounts(),clock=lambda:self.now)
        with self.assertRaises(BridgeError):self.boot(FORK,'fork')
        self.boot(FORK,'fork',peer='work@pop-os')
    def test_account_allowlist_owner_revocation_and_ntc_denied(self):
        with self.assertRaises(BridgeError):self.boot(peer='ntc@laptop')
        cfg=accounts();cfg['accounts']['ntc@laptop']={'enabled':True,'clients':['codex']}
        with self.assertRaises(BridgeError):SessionLeases(self.store,cfg)
        b=self.boot();self.cfg['owners']['bits255']['enabled']=False
        p=self.leases.project(Policy(self.cfg))
        with self.assertRaises(BridgeError):p.authenticate('Bearer '+TOKENS['auto'])
    def test_active_capacity_reclaimed_on_expiry_without_deleting_history(self):
        self.leases.config['max_active']=1;b=self.boot();self.send(b)
        with self.assertRaises(BridgeError):self.boot(FORK,'fork')
        self.now=b['deadline'];self.boot(FORK,'fork')
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM trusted_sessions').fetchone()[0],2)
        self.assertEqual(len(self.store.history()),1)
        with self.assertRaises(BridgeError):self.boot(token='rotated',kind='resume',event='resume-event-0001')
    def test_history_capacity_fail_closed_without_deletion(self):
        self.leases.config.update(max_active=1,max_records=1);b=self.boot();self.now=b['deadline']
        with self.assertRaises(BridgeError) as exc:self.boot(FORK,'fork')
        self.assertEqual(exc.exception.status,507);self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM trusted_sessions').fetchone()[0],1)
    def test_claims_history_and_dedupe_survive_expiry_resume(self):
        b=self.boot();m=self.send(b)['message'];self.store.claim_message(m['id'],EMBER,'sister-claim-001')
        snapshot=[dict(r) for r in self.store.db.execute('SELECT * FROM message_claims')]
        self.now=b['deadline'];self.leases.cleanup()
        self.assertEqual(snapshot,[dict(r) for r in self.store.db.execute('SELECT * FROM message_claims')])
        self.boot(token='rotated',kind='resume',event='resume-event-0001')
        self.assertTrue(self.send(b)['duplicate']);self.assertEqual(len(self.store.history()),1)
    def test_owned_wake_cleanup_parks_and_quarantines_without_touching_sister(self):
        b=self.boot();m=self.send(b)['message']
        with self.store.transaction():
            for sid,role in (('owned-sub-0001',b['participant']),('sister-sub-0001',EMBER)):
                self.store.db.execute("INSERT INTO subscriptions(id,role,url,secret,auth_digest,expires,verified_until,active,created) VALUES(?,?,'https://example.test','synthetic-signing-key','synthetic',?,0,1,?)",(sid,role,self.now+200000,self.now))
            for sid,status in (('owned-sub-0001','pending'),('sister-sub-0001','pending')):
                self.store.db.execute("INSERT INTO outbox(subscription_id,message_id,event_id,body,status,next_attempt) VALUES(?,?,?,'{}',?,0)",(sid,m['id'],'event-'+sid,status))
            m2=self.store.db.execute('SELECT seq FROM outbox WHERE subscription_id=\'owned-sub-0001\'').fetchone()[0]
            self.store.db.execute("UPDATE outbox SET status='leased',lease_token='synthetic-attempt',lease_until=? WHERE seq=?",(self.now+100,m2))
        sister=dict(self.store.db.execute("SELECT * FROM subscriptions WHERE role=?",(EMBER,)).fetchone())
        self.now=b['deadline'];self.assertEqual(self.leases.cleanup(),1);self.assertEqual(self.leases.cleanup(),0)
        self.assertEqual(dict(self.store.db.execute("SELECT * FROM subscriptions WHERE role=?",(EMBER,)).fetchone()),sister)
        self.assertEqual(self.store.db.execute("SELECT status FROM outbox WHERE subscription_id='owned-sub-0001'").fetchone()[0],'quarantined')
        self.assertEqual(self.store.db.execute("SELECT status FROM outbox WHERE subscription_id='sister-sub-0001'").fetchone()[0],'pending')
        self.boot(token='rotated',kind='resume',event='resume-event-0001')
        self.assertEqual(self.store.db.execute("SELECT active FROM subscriptions WHERE role=?",(b['participant'],)).fetchone()[0],0)
    def test_clock_backwards_fails_leased_actor_closed_but_manual_stays_up(self):
        b=self.boot();self.now-=1;p=self.leases.project(self.base)
        with self.assertRaises(BridgeError):p.authenticate('Bearer '+TOKENS['auto'])
        self.assertEqual(p.authenticate('Bearer '+TOKENS[EMBER]),EMBER)
        with self.assertRaises(BridgeError):self.boot()
        self.leases.revoke(peer='mikkel@pop-os')
    def test_stale_scope_cannot_send_at_deadline(self):
        b=self.boot();scope=self.scoped(b['participant']);self.now=b['deadline']
        with self.assertRaises(BridgeError):scope.stage(b['participant'],EMBER,text='A late report must not be committed.',message_id='late-message-0001',conversation_id=b['conversation'],provenance='mcp')
        self.assertEqual(self.store.history(),[])
    def test_existing_credential_or_explicit_identity_collision_is_denied(self):
        with self.assertRaises(BridgeError):self.boot(token=EMBER)
        b=self.boot();cfg=copy.deepcopy(self.cfg);p,c,s=b['participant'].split('.')
        cfg['participants'][b['participant']]={'owner':p,'client':c,'session':s,'state':'active','accepted':True,'activated_at':int(self.now)-60,'expires':None,'sha256':sha(TOKENS['rotated'])}
        with self.assertRaises(BridgeError):self.leases.bootstrap(Policy(cfg),peer='mikkel@pop-os',client='codex',native_id=SID,sha256=sha(TOKENS['auto']),event_id='bootstrap-0002')
    def test_projection_can_reproject_without_duplicate_roles(self):
        b=self.boot();p=self.leases.project(self.base);p2=self.leases.project(p)
        self.assertEqual(p.agents,p2.agents);self.store.sync_policy(p2)
        self.now=b['deadline'];p3=self.leases.project(p2);self.store.sync_policy(p3)
        self.assertNotIn(b['participant'],p3.agents)
        self.assertFalse(self.store.db.execute('SELECT 1 FROM participant_bindings WHERE id=?',(b['participant'],)).fetchone())
    def test_private_requests_reject_extra_fields_and_missing_adapter(self):
        r=request('codex',sha(TOKENS['auto']),env={'CODEX_THREAD_ID':SID})
        out=apply(self.store,accounts(),self.base,'mikkel@pop-os',r);self.assertIn('participant',out)
        for key in ('peer','recipient','timestamp','active'):
            rr=dict(r);rr[key]='forged'
            with self.assertRaises(BridgeError):apply(self.store,accounts(),self.base,'mikkel@pop-os',rr)
        for client in ('opencode','grokbot','muse'):
            with self.assertRaises(BridgeError):context(client,env={})
    def test_context_adapters_canonical_reconnect_fork_and_hosted_denied(self):
        self.assertEqual(context('codex',env={'CODEX_THREAD_ID':SID.upper()})['native_id'],SID)
        self.assertNotEqual(context('codex',env={'CODEX_THREAD_ID':SID}),context('codex',env={'CODEX_THREAD_ID':FORK}))
        self.assertEqual(context('claude',env={},hook={'hook_event_name':'SessionStart','session_id':SID})['kind'],'bootstrap')
        self.assertEqual(context('cursor',env={},hook={'hook_event_name':'sessionStart','session_id':SID,'conversation_id':SID})['native_id'],SID)
        with self.assertRaises(BridgeError):context('claude',env={'CLAUDE_CODE_REMOTE':'true'},hook={'hook_event_name':'SessionStart','session_id':SID})
        with self.assertRaises(BridgeError):context('cursor',env={},hook={'hook_event_name':'sessionStart','session_id':SID,'conversation_id':FORK})

class ConcurrencyTests(unittest.TestCase):
    def test_two_connections_concurrent_start_reconnect_and_resume_are_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            now=time.time();base=Policy(fixture(now));stores=[Store(Path(d)/'fixture.sqlite3') for _ in range(2)]
            leases=[SessionLeases(s,accounts(),clock=lambda:now) for s in stores]
            results=[];errors=[];barrier=threading.Barrier(2)
            def boot(lease,token,kind,event):
                try:
                    barrier.wait();results.append(lease.bootstrap(base,peer='mikkel@pop-os',client='codex',native_id=SID,sha256=sha(TOKENS[token]),kind=kind,event_id=event))
                except Exception as e:errors.append(e)
            try:
                ts=[threading.Thread(target=boot,args=(l,'auto','bootstrap','startup-event-01')) for l in leases]
                for t in ts:t.start()
                for t in ts:t.join()
                self.assertEqual(errors,[]);self.assertEqual(results[0],results[1])
                now=results[0]['deadline'];results.clear()
                ts=[threading.Thread(target=boot,args=(l,'rotated','resume','resume-event-0001')) for l in leases]
                for t in ts:t.start()
                for t in ts:t.join()
                self.assertEqual(errors,[]);self.assertEqual(results[0],results[1]);self.assertEqual(results[0]['generation'],2)
            finally:
                for s in stores:s.close()

class HelperTests(unittest.TestCase):
    def test_fixture_credentials_reconnect_fork_no_global_config_or_real_secret(self):
        with tempfile.TemporaryDirectory() as d,patch('pwd.getpwuid',return_value=SimpleNamespace(pw_name='mikkel')):
            Path(d).chmod(0o700);tokens=iter((TOKENS['auto'],TOKENS['fork'],TOKENS['rotated']))
            h=Helper(Path(d)/'instances','mikkel@pop-os',token_factory=lambda:next(tokens))
            ctx=context('codex',env={'CODEX_THREAD_ID':SID});a,token,r=h.prepare(ctx)
            a2,token2,r2=h.prepare(ctx);self.assertEqual((a,token,r),(a2,token2,r2))
            b,_,_=h.prepare(context('codex',env={'CODEX_THREAD_ID':FORK}));self.assertNotEqual(a,b)
            candidate=h.prepare(ctx,'native-resume-0001')[1];self.assertEqual(candidate.name,'resume-token')
            self.assertEqual(token.read_text().strip(),TOKENS['auto'])
            with patch.object(h,'call',return_value={'contacts':[{'recipient':EMBER,'conversation_id':'synthetic-conversation'}]}):h.verify(a,candidate)
            self.assertEqual(token.read_text().strip(),TOKENS['rotated'])
            for p in a.iterdir():self.assertEqual(p.stat().st_mode & 0o777,0o600)
    def test_ntc_denied_and_symlink_request_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            with patch('pwd.getpwuid',return_value=SimpleNamespace(pw_name='ntc')):
                with self.assertRaises(BridgeError):Helper(Path(d)/'instances','mikkel@pop-os')
            with patch('pwd.getpwuid',return_value=SimpleNamespace(pw_name='mikkel')):
                h=Helper(Path(d)/'instances','mikkel@pop-os',token_factory=lambda:TOKENS['auto']);ctx=context('codex',env={'CODEX_THREAD_ID':SID})
                path=h.prepare(ctx)[0];f=path/'trusted-enrollment.json';f.unlink();f.symlink_to(Path(d)/'outside')
                with self.assertRaises(BridgeError):h.prepare(ctx)

class GatewayLeaseTests(unittest.TestCase):
    def test_real_loopback_gateway_reports_then_idle_denies_with_manual_unchanged(self):
        now=[time.time()];store=Store(':memory:');base=Policy(fixture(now[0]));leases=SessionLeases(store,accounts(),clock=lambda:now[0])
        b=leases.bootstrap(base,peer='mikkel@pop-os',client='codex',native_id=SID,sha256=sha(TOKENS['auto']),event_id='startup-event-01')
        server=Gateway(0,base,'https://babel.example.test',store=store);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            opener=build_opener(ProxyHandler({}));url='http://127.0.0.1:'+str(server.port)+'/mcp/v1'
            def call(token):
                data={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'list_contacts','arguments':{}}}
                req=Request(url,data=json.dumps(data).encode(),headers={'Host':'babel.example.test','X-Forwarded-Proto':'https','Authorization':'Bearer '+token,'Content-Type':'application/json','Accept':'application/json, text/event-stream'})
                return json.load(opener.open(req,timeout=3))
            self.assertEqual(json.loads(call(TOKENS['auto'])['result']['content'][0]['text'])['contacts'][0]['recipient'],EMBER)
            now[0]=b['deadline']
            with self.assertRaises(HTTPError) as e:call(TOKENS['auto'])
            self.assertIn(e.exception.code,(401,403));self.assertFalse(call(TOKENS[MANUAL])['result']['isError'])
        finally:server.shutdown();server.server_close();thread.join();store.close()

class MigrationTests(unittest.TestCase):
    setUp=LeaseTests.setUp
    tearDown=LeaseTests.tearDown
    scoped=LeaseTests.scoped
    def adopt(self,**kwargs):return self.leases.adopt(self.base,peer='mikkel@pop-os',participant=MANUAL,native_id=SID,**kwargs)
    def test_existing_grants_server_evidence_and_live_subscription_are_preserved(self):
        msg=self.scoped(MANUAL).stage(MANUAL,ADA,message_id='manual-task-report-01',text='Completed the requested work and checked its output.',conversation_id='manual_ada_chat',provenance='mcp')
        activity=self.now;self.now+=600
        self.store.db.execute("INSERT INTO subscriptions(id,role,url,secret,auth_digest,expires,verified_until,active,created) VALUES('legacy-subscription',?,'https://example.test','synthetic-key',?,?,0,1,?)",(MANUAL,self.base.agents[MANUAL][0],self.now+100000,self.now));self.store.db.commit()
        subscription=dict(self.store.db.execute("SELECT * FROM subscriptions WHERE id='legacy-subscription'").fetchone())
        b=self.adopt();self.assertEqual(b['deadline'],activity+IDLE_SECONDS)
        p=self.leases.project(self.base);self.store.sync_policy(p)
        self.assertEqual(p.routes,self.base.routes);self.assertEqual(p.conversations,self.base.conversations)
        self.assertEqual(subscription,dict(self.store.db.execute("SELECT * FROM subscriptions WHERE id='legacy-subscription'").fetchone()))
        self.assertEqual({c['recipient'] for c in self.scoped(MANUAL).contacts(MANUAL)},{EMBER,ADA})
        self.assertEqual(self.scoped(MANUAL).message_status(msg['message']['id'],MANUAL)['status'],'queued')
        self.assertEqual(self.adopt(),b)
    def test_absent_historical_evidence_gets_exact_bounded_rollout_grace(self):
        b=self.adopt();self.assertEqual(b['deadline'],self.now+86400)
        evidence=self.store.db.execute("SELECT kind FROM trusted_session_evidence WHERE participant=?",(MANUAL,)).fetchone()[0]
        self.assertEqual(evidence,'rollout_grace');self.now+=1000;self.assertEqual(self.adopt(),b)
    def test_old_substantial_report_expires_on_migration_without_deleting_it(self):
        self.scoped(MANUAL).stage(MANUAL,EMBER,message_id='old-manual-report-01',text='Historical work report retained for the operator.',conversation_id='manual_ember_chat',provenance='mcp')
        self.now+=86401;b=self.adopt();self.assertEqual(b['state'],'idle_expired');self.assertEqual(len(self.store.history()),1)
        with self.assertRaises(BridgeError):self.scoped(MANUAL).contacts(MANUAL)
    def test_claim_ack_status_and_sister_activity_do_not_renew_migrated_worker(self):
        b=self.adopt();self.now+=600
        row=self.scoped(EMBER).stage(EMBER,MANUAL,message_id='incoming-sister-report',text='Selected work for the already authorized worker.',conversation_id='manual_ember_chat',provenance='mcp')['message']
        s=self.scoped(MANUAL);s.claim_message(row['id'],MANUAL,'worker-claim-001');s.acknowledge(row['id'],MANUAL,'worker-claim-001');s.message_status(row['id'],MANUAL)
        self.assertEqual(self.leases.row(MANUAL)['deadline'],b['deadline'])
    def test_idle_legacy_resume_rotates_and_retains_both_explicit_routes(self):
        b=self.adopt();scope=self.scoped(MANUAL);self.now=b['deadline'];self.leases.cleanup()
        out=self.leases.bootstrap(self.base,peer='mikkel@pop-os',client='codex',native_id=SID,sha256=sha(TOKENS['rotated']),kind='resume',event_id='legacy-resume-0001')
        self.assertEqual(out['participant'],MANUAL)
        p=self.leases.project(self.base);self.store.sync_policy(p)
        self.assertEqual(p.routes,self.base.routes)
        self.assertEqual(p.authenticate('Bearer '+TOKENS['rotated']),MANUAL)
        with self.assertRaises(BridgeError):p.authenticate('Bearer '+TOKENS[MANUAL])
        with self.assertRaises(BridgeError):scope.contacts(MANUAL)
        self.assertEqual(len(self.scoped(MANUAL).contacts(MANUAL)),2)
        with self.assertRaises(BridgeError):self.leases.bootstrap(self.base,peer='mikkel@pop-os',client='codex',native_id=SID,sha256=sha(TOKENS['fork']),kind='resume',event_id='legacy-resume-0001')
    def test_infrastructure_wrong_account_and_binding_reassignment_are_denied(self):
        for pid in (EMBER,ADA):
            with self.assertRaises(BridgeError):self.leases.adopt(self.base,peer='mikkel@pop-os',participant=pid,native_id=SID)
        self.adopt()
        with self.assertRaises(BridgeError):self.leases.adopt(self.base,peer='work@pop-os',participant=MANUAL,native_id=SID)
        with self.assertRaises(BridgeError):self.leases.adopt(self.base,peer='mikkel@pop-os',participant=MANUAL,native_id=FORK)
    def test_explicit_revoke_remains_permanent_after_migration(self):
        self.adopt();cfg=copy.deepcopy(self.cfg);cfg['participants'][MANUAL]['state']='revoked'
        self.store.sync_policy(self.leases.project(Policy(cfg)))
        with self.assertRaises(BridgeError):self.leases.bootstrap(self.base,peer='mikkel@pop-os',client='codex',native_id=SID,sha256=sha(TOKENS['rotated']),kind='resume',event_id='legacy-resume-0001')

    def test_legacy_alias_upgrade_preserves_mailbox_and_cannot_take_other_context(self):
        alias='legacy:'+sha(MANUAL)[:32]
        self.leases.adopt(self.base,peer='mikkel@pop-os',participant=MANUAL,native_id=alias)
        out=self.leases.bootstrap(self.base,peer='mikkel@pop-os',client='codex',native_id=SID,sha256=sha(TOKENS[MANUAL]),event_id='native-startup-001',existing_participant=MANUAL)
        self.assertEqual(out['participant'],MANUAL);self.assertEqual(self.leases.row(MANUAL)['native_id'],SID)
        for peer,sid in (('work@pop-os',SID),('mikkel@pop-os',FORK)):
            with self.assertRaises(BridgeError):self.leases.bootstrap(self.base,peer=peer,client='codex',native_id=sid,sha256=sha(TOKENS[MANUAL]),event_id='other-startup-001',existing_participant=MANUAL)

    def test_removing_lifecycle_flag_never_revives_old_legacy_credential(self):
        b=self.adopt();self.now=b['deadline'];self.leases.cleanup()
        self.leases.bootstrap(self.base,peer='mikkel@pop-os',client='codex',native_id=SID,sha256=sha(TOKENS['rotated']),kind='resume',event_id='legacy-resume-0001')
        self.store.sessions=None
        p=self.store.authorized_policy(self.base);self.store.sync_policy(p)
        for token in (TOKENS[MANUAL],TOKENS['rotated']):
            with self.assertRaises(BridgeError):p.authenticate('Bearer '+token)
        self.assertEqual(p.authenticate('Bearer '+TOKENS[ADA]),ADA)
        self.store.sessions=self.leases
        p=self.store.authorized_policy(self.base);self.assertEqual(p.authenticate('Bearer '+TOKENS['rotated']),MANUAL)
    def test_explicit_policy_removal_and_downgrade_keep_permanent_revocation(self):
        self.adopt();cfg=copy.deepcopy(self.cfg);cfg['participants'].pop(MANUAL);cfg['conversations']={}
        self.store.sync_policy(self.leases.project(Policy(cfg)))
        self.assertEqual(self.leases.row(MANUAL)['state'],'revoked')
        with self.assertRaises(BridgeError):self.leases.bootstrap(self.base,peer='mikkel@pop-os',client='codex',native_id=SID,sha256=sha(TOKENS['rotated']),kind='resume',event_id='legacy-resume-0001')
        from babel.session_leases import rollback_policy
        reverted=rollback_policy(self.cfg,self.store)
        self.assertEqual(reverted['participants'][MANUAL]['state'],'revoked');self.assertEqual(reverted['conversations'],self.cfg['conversations'])
        self.store.sessions=None;self.store.sync_policy(Policy(reverted))
    def test_unknown_native_clients_can_migrate_by_account_instance_only(self):
        cfg=copy.deepcopy(self.cfg);pid='bits255.opencode.legacy_01'
        cfg['participants'][pid]=dict(cfg['participants'][MANUAL],client='opencode',session='legacy_01',sha256=sha(TOKENS['fork']))
        cfg['conversations']['old_opencode_report']={'state':'active','participants':[pid,EMBER],'routes':[{'sender':pid,'recipient':EMBER}]}
        base=Policy(cfg);self.leases.config['accounts']['mikkel@pop-os']['clients'].append('opencode')
        native='legacy:'+sha(pid)[:32]
        with self.assertRaises(BridgeError):self.leases.bootstrap(base,peer='mikkel@pop-os',client='opencode',native_id=native,sha256=sha(TOKENS['auto']),event_id='startup-event-01')
        result=self.leases.adopt(base,peer='mikkel@pop-os',participant=pid,native_id=native)
        self.assertEqual(result['participant'],pid)

class CollectorTests(unittest.TestCase):
    def test_digest_only_collector_fair_progress_retries_and_server_idempotence(self):
        from collect_account_sessions import collect,apply_pending,validate
        from babel.account_bootstrap import local_key
        with tempfile.TemporaryDirectory() as d:
            Path(d).chmod(0o700);now=[time.time()];store=Store(Path(d)/'fixture.sqlite3');base=Policy(fixture(now[0]));leases=SessionLeases(store,accounts(cap=8),clock=lambda:now[0])
            requests=[];items=[];seen=[]
            for n in range(6):
                sid=SID[:-1]+str(n);r=request('codex',sha('public-synthetic-worker-credential-'+str(n).zfill(12)),env={'CODEX_THREAD_ID':sid});requests.append(r)
                items.append({'folder':'codex-auto_'+local_key('mikkel@pop-os',r),'request':r})
            def runner(argv,**kwargs):
                if argv[-1]=='mikkel@pop-os':
                    r=json.loads(kwargs['input']);seen.append(r);out=apply(store,accounts(cap=8),base,'mikkel@pop-os',r)
                    return SimpleNamespace(returncode=0,stdout=json.dumps(out))
                self.assertIn('StrictHostKeyChecking=yes',argv)
                return SimpleNamespace(returncode=0,stdout=json.dumps(items))
            try:
                rs=collect('mikkel@pop-os',runner);ledger=Path(d)/'collector.json'
                self.assertEqual(apply_pending('mikkel@pop-os',rs,ledger,runner),4)
                self.assertEqual(apply_pending('mikkel@pop-os',rs,ledger,runner),2)
                now[0]+=1000;self.assertEqual(apply_pending('mikkel@pop-os',rs,ledger,runner),0)
                self.assertEqual(len(seen),6);self.assertEqual(store.db.execute('SELECT COUNT(*) FROM trusted_sessions').fetchone()[0],6)
                with self.assertRaises(BridgeError):collect('ntc@laptop',runner)
                bad=dict(items[0]);bad['folder']='codex-auto_'+'0'*32
                with self.assertRaises(BridgeError):validate('mikkel@pop-os',bad)
            finally:store.close()
    def test_migrated_helper_rotates_in_place_and_keeps_legacy_manifest_compatible(self):
        with tempfile.TemporaryDirectory() as d,patch('pwd.getpwuid',return_value=SimpleNamespace(pw_name='mikkel')):
            root=Path(d);root.chmod(0o700);legacy=root/'legacy';legacy.mkdir(mode=0o700)
            from account_session_helper import save
            save(legacy/'token',TOKENS[MANUAL]+'\n');manifest={'schema_version':1,'client':'codex','participant':MANUAL,'session':'manual_01','sha256':sha(TOKENS[MANUAL])}
            save(legacy/'enrollment.json',json.dumps(manifest))
            h=Helper(root/'automatic-instances','mikkel@pop-os',token_factory=lambda:TOKENS['rotated']);ctx=context('codex',env={'CODEX_THREAD_ID':SID});h.use_legacy(ctx,legacy)
            p,c,r=h.prepare(ctx,'legacy-resume-0001');self.assertEqual(p,legacy)
            self.assertEqual((legacy/'token').read_text().strip(),TOKENS[MANUAL])
            with patch.object(h,'call',return_value={'contacts':[{'recipient':EMBER,'conversation_id':'manual_ember_chat'},{'recipient':ADA,'conversation_id':'manual_ada_chat'}]}):h.verify(p,c)
            self.assertEqual(json.loads((legacy/'enrollment.json').read_text())['sha256'],sha((legacy/'token').read_text().strip()))
            _,c2,r2=h.prepare(ctx,'legacy-resume-0001');self.assertEqual(c2,legacy/'token');self.assertEqual(r2,r)

class RecoveryTests(unittest.TestCase):
    def test_fixture_rotation_crash_journal_recovers_without_another_credential(self):
        from account_session_helper import save,recover_rotation
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);p.chmod(0o700)
            save(p/'token',TOKENS['auto']+'\n');save(p/'resume-token',TOKENS['rotated']+'\n')
            save(p/'enrollment.json',json.dumps({'schema_version':1,'client':'codex','participant':MANUAL,'session':'manual_01','sha256':sha(TOKENS['auto'])}))
            save(p/'resume-event.json',json.dumps({'event_id':'native-resume-0001'}))
            save(p/'rotation-journal.json',json.dumps({'event_id':'native-resume-0001','sha256':sha(TOKENS['rotated'])}))
            recover_rotation(p);recover_rotation(p)
            self.assertEqual((p/'token').read_text().strip(),TOKENS['rotated'])
            self.assertEqual(json.loads((p/'enrollment.json').read_text())['sha256'],sha(TOKENS['rotated']))
            self.assertFalse((p/'rotation-journal.json').exists())
    def test_report_requires_stable_id_and_repeated_self_pings_do_not_renew(self):
        now=[time.time()];s=Store(':memory:');base=Policy(fixture(now[0]));l=SessionLeases(s,accounts(),clock=lambda:now[0])
        try:
            b=l.bootstrap(base,peer='mikkel@pop-os',client='codex',native_id=SID,sha256=sha(TOKENS['auto']),event_id='startup-event-01');p=l.project(base);sc=ScopedStore(s,b['participant'],p.agents[b['participant']][1],p)
            with self.assertRaises(BridgeError):sc.stage(b['participant'],EMBER,text='A legitimate report needs its stable retry identifier.',conversation_id=b['conversation'],provenance='mcp')
            now[0]+=600;sc.stage(b['participant'],EMBER,text='ping ping ping ping ping',message_id='repeated-ping-0001',conversation_id=b['conversation'],provenance='mcp')
            self.assertEqual(l.row(b['participant'])['deadline'],b['deadline'])
        finally:s.close()


class SendExpiryRaceTests(unittest.TestCase):
    def test_sqlite_serialization_fences_send_waiting_during_expiry(self):
        with tempfile.TemporaryDirectory() as d:
            now=[time.time()];base=Policy(fixture(now[0]));stores=[Store(Path(d)/'fixture.sqlite3') for _ in range(2)]
            leases=[SessionLeases(s,accounts(),clock=lambda:now[0]) for s in stores]
            b=leases[0].bootstrap(base,peer='mikkel@pop-os',client='codex',native_id=SID,sha256=sha(TOKENS['auto']),event_id='startup-event-01')
            p=leases[0].project(base);scope=ScopedStore(stores[0],b['participant'],p.agents[b['participant']][1],p)
            starting=threading.Event();errors=[]
            def send():
                starting.set()
                try:scope.stage(b['participant'],EMBER,text='This report must not race past idle expiry.',message_id='racing-expiry-report',conversation_id=b['conversation'],provenance='mcp')
                except Exception as e:errors.append(e)
            try:
                stores[1].db.execute('BEGIN IMMEDIATE');t=threading.Thread(target=send);t.start();self.assertTrue(starting.wait(1))
                now[0]=b['deadline'];stores[1].db.commit();t.join(3)
                self.assertFalse(t.is_alive());self.assertEqual(len(errors),1);self.assertIsInstance(errors[0],BridgeError)
                self.assertEqual(stores[0].history(),[])
            finally:
                for s in stores:s.close()


class LegacyAdmissionTests(unittest.TestCase):
    def test_legacy_new_admission_flag_and_pinned_marker_fail_closed(self):
        from babel.legacy_admission import assert_legacy_admission
        with tempfile.TemporaryDirectory() as d:
            db=Path(d)/'absent.sqlite3';marker=Path(d)/'accounts.json'
            for peer in ('mikkel@pop-os','work@pop-os'):
                # No peer field in schema1: both unattended callers share endpoint.
                with self.subTest(peer=peer),self.assertRaises(BridgeError):
                    assert_legacy_admission(False,db,env={'BABEL_TRUSTED_ACCOUNTS_FILE':str(marker)},accounts_path=marker)
            marker.write_text('{}')
            with self.assertRaises(BridgeError):assert_legacy_admission(False,db,env={},accounts_path=marker)
            self.assertFalse(db.exists())

    def test_legacy_durable_guard_survives_flag_removal_and_existing_reconnect(self):
        from babel.legacy_admission import assert_legacy_admission
        with tempfile.TemporaryDirectory() as d:
            store=Store(Path(d)/'fixture.sqlite3')
            try:
                SessionLeases(store,accounts())
                before=[dict(r) for r in store.db.execute('SELECT * FROM trusted_session_realms')]
                with self.assertRaises(BridgeError):assert_legacy_admission(False,Path(d)/'fixture.sqlite3',env={},accounts_path=Path(d)/'absent')
                assert_legacy_admission(True,Path(d)/'fixture.sqlite3',env={},accounts_path=Path(d)/'absent')
                self.assertEqual(before,[dict(r) for r in store.db.execute('SELECT * FROM trusted_session_realms')])
            finally:store.close()

    def test_disabled_legacy_behavior_and_explicit_private_permanent_edit_unchanged(self):
        from babel.legacy_admission import assert_legacy_admission
        from babel.enrollment import change
        with tempfile.TemporaryDirectory() as d:
            assert_legacy_admission(False,Path(d)/'absent.sqlite3',env={},accounts_path=Path(d)/'absent')
        cfg=fixture(time.time())
        result=change(cfg,'invite',owner='bits255',client='codex',session='deliberate_01')
        self.assertIsNone(result['participants']['bits255.codex.deliberate_01']['expires'])
        self.assertNotIn('bits255.codex.deliberate_01',cfg['participants'])

    def test_actual_legacy_operator_rejects_new_requests_before_policy_or_db_write(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('legacy_review_operator',Path(__file__).resolve().parents[1]/'deploy/legacy-enroll-worker.py')
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as d:
            policy=Path(d)/'policy.json';db=Path(d)/'absent.sqlite3';req=Path(d)/'request.json'
            cfg=fixture(time.time());cfg['approval']='automatic';policy.write_text(json.dumps(cfg));original=policy.read_bytes()
            for peer in ('mikkel@pop-os','work@pop-os'):
                request={'schema_version':1,'participant':'bits255.codex.fresh_0123456789abcdef','client':'codex','session':'fresh_0123456789abcdef','sha256':sha(TOKENS['auto'])}
                req.write_text(json.dumps(request))
                with patch.object(mod,'POLICY_PATH',policy),patch.object(mod,'DB_PATH',str(db)),patch.dict('os.environ',{'BABEL_TRUSTED_ACCOUNTS_FILE':str(Path(d)/'accounts.json')}):
                    with self.subTest(peer=peer),self.assertRaisesRegex(BridgeError,'New schema1'):
                        mod.apply(req)
                self.assertEqual(policy.read_bytes(),original);self.assertFalse(db.exists());self.assertFalse((Path(d)/'policy.json.new').exists())

    def test_actual_legacy_operator_existing_reconnect_preserves_grants_and_no_renewal(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('legacy_existing_operator',Path(__file__).resolve().parents[1]/'deploy/legacy-enroll-worker.py')
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        class FixturePolicy(Policy):
            def __init__(self,cfg):super().__init__(cfg);self.bindings={}
        with tempfile.TemporaryDirectory() as d:
            pid='bits255.codex.review_0123456789abcdef';cfg=fixture(time.time());cfg['approval']='automatic'
            entry=cfg['participants'].pop(MANUAL);entry.update(session='review_0123456789abcdef');cfg['participants'][pid]=entry;cfg['conversations']={}
            for name,hub in mod.HUBS.items():
                cfg['conversations']['report_codex_0123456789abcdef_'+name]={'state':'active','participants':[pid,hub],'routes':[{'sender':pid,'recipient':hub},{'sender':hub,'recipient':pid}]}
            policy=Path(d)/'policy.json';policy.write_text(json.dumps(cfg));original=policy.read_bytes();db=Path(d)/'absent.sqlite3';req=Path(d)/'request.json'
            req.write_text(json.dumps({'schema_version':1,'participant':pid,'client':'codex','session':entry['session'],'sha256':entry['sha256']}))
            with patch.object(mod,'POLICY_PATH',policy),patch.object(mod,'DB_PATH',str(db)),patch.object(mod,'OAuthPolicy',FixturePolicy),patch.dict('os.environ',{'BABEL_TRUSTED_ACCOUNTS_FILE':str(Path(d)/'accounts.json')}):
                result=mod.apply(req)
                self.assertFalse(result['changed']);self.assertEqual({r['recipient'] for r in result['contacts']},{EMBER,ADA})
                altered=json.loads(req.read_text());altered['sha256']=sha(TOKENS['rotated']);req.write_text(json.dumps(altered))
                with self.assertRaises(AssertionError):mod.apply(req)
            self.assertEqual(policy.read_bytes(),original);self.assertFalse(db.exists())
