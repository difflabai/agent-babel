"""Synthetic native hook fixtures and actual off-production gateway contracts."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener
from account_lifecycle_hook import Dispatcher
from account_session_helper import Helper, save
from babel.account_bootstrap import context
from babel.native_lifecycle import parse
from babel.core import BridgeError, Store
from babel.auth import Policy
from babel.gateway import Gateway
from babel.channel_events import ApprovalSource
from babel.auth import ScopedStore
from babel.session_leases import SessionLeases, IDLE_SECONDS
from babel.session_operator import apply
from collect_account_sessions import collect, apply_pending, validate
from tests.test_session_leases import fixture, accounts, SID, FORK, EMBER, MANUAL, TOKENS, sha

TURN='10000000-0000-4000-8000-000000000001'
TURN2='10000000-0000-4000-8000-000000000002'


class DispatcherTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.now=time.time()-100
        self.uid=patch('pwd.getpwuid',return_value=SimpleNamespace(pw_name='mikkel'));self.uid.start()
        self.tokens=iter(['synthetic-only-credential-'+str(n).zfill(32) for n in range(20)])
        self.helper=Helper(self.root/'.config/255bits/agent-babel/automatic-instances','mikkel@pop-os',token_factory=lambda:next(self.tokens))
        self.dispatcher=Dispatcher(self.helper,clock=lambda:self.now,invocation=lambda:'fixture-runtime-1')
    def tearDown(self): self.uid.stop(); self.tmp.cleanup()
    def hook(self,event='SessionStart',client='codex',sid=SID,**kwargs):
        raw={'hook_event_name':event,'session_id':sid,**kwargs}
        if event=='SessionStart':raw.setdefault('source','startup')
        return self.dispatcher.dispatch(client,raw,env={})
    def records(self,client='codex',sid=SID):
        p=self.helper.path({'client':client,'native_id':sid})
        return [json.loads(f.read_text()) for f in sorted((p/'lifecycle-events').glob('*.json'))]
    def runner(self,store,leases,base):
        def run(argv,**kw):
            if '/usr/local/sbin/agent-babel-trusted-session' in argv:
                r=json.loads(kw['input']);out=apply(store,accounts(),base,'mikkel@pop-os',r)
                return SimpleNamespace(returncode=0,stdout=json.dumps(out))
            env={**os.environ,'HOME':str(self.root)}
            return subprocess.run(['python3','-c',shlex.split(argv[-1])[0]],
                input=kw.get('input'),capture_output=True,text=True,env=env,timeout=5)
        return run
    def test_real_hook_context_no_env_fork_distinct_and_mismatch_rejected(self):
        self.assertEqual(context('codex',env={},hook={'hook_event_name':'SessionStart','session_id':SID})['native_id'],SID)
        self.hook();self.hook(sid=FORK)
        self.assertEqual(len(list(self.helper.root.iterdir())),2)
        with self.assertRaises(BridgeError):parse('codex',{'session_id':SID,'hook_event_name':'SessionStart','source':'startup'},env={'CODEX_THREAD_ID':FORK})
    def test_codex_prompt_stop_duplicate_and_maintenance_never_renew(self):
        self.hook();self.now+=5
        self.hook('UserPromptSubmit',turn_id=TURN,prompt='Build the requested integration.')
        self.now+=5;self.hook('Stop',turn_id=TURN)
        before=self.records();self.now+=100
        self.hook('Stop',turn_id=TURN);self.hook('UserPromptSubmit',turn_id=TURN,prompt='Build the requested integration.')
        self.hook('UserPromptSubmit',turn_id=TURN2,prompt='Babel mailbox notification for this participant')
        self.hook('Stop',turn_id=TURN2)
        self.hook(source='compact');self.hook('PostToolUse',turn_id=TURN2)
        self.assertEqual(self.records(),before);self.assertEqual(len(before),3)
        self.assertNotIn('integration',json.dumps(before))
        self.assertNotIn('prompt',json.dumps(before))
    def test_hosted_subagents_and_unsupported_clients_fail_closed(self):
        with self.assertRaises(BridgeError):parse('claude',{'hook_event_name':'SessionStart','session_id':SID,'source':'startup'},env={'CLAUDE_CODE_REMOTE':'true'})
        self.assertIsNone(parse('codex',{'hook_event_name':'SessionStart','session_id':SID,'source':'startup','agent_id':'subagent'}))
        for client in ('cursor','opencode','grokbot','muse'):
            with self.assertRaises(BridgeError):parse(client,{'session_id':SID})
    def test_no_completion_without_correlated_real_prompt(self):
        self.hook();self.hook('Stop',turn_id=TURN)
        self.assertEqual(len(self.records()),1)
        self.hook('UserPromptSubmit',turn_id=TURN,prompt='heartbeat ping active')
        self.hook('Stop',turn_id=TURN)
        self.assertEqual(len(self.records()),1)
    def test_correlated_codex_edit_activity_dedups_without_babel_or_shell_poll_renewal(self):
        self.hook();self.hook('UserPromptSubmit',turn_id=TURN,prompt='Implement the change.')
        self.now+=100
        self.hook('PostToolUse',turn_id=TURN,tool_name='apply_patch',tool_use_id='call_fixture_0001',tool_input={'command':'PRIVATE CONTENT'},tool_response='PRIVATE CONTENT')
        before=self.records();self.now+=100
        self.hook('PostToolUse',turn_id=TURN,tool_name='apply_patch',tool_use_id='call_fixture_0001')
        self.hook('PostToolUse',turn_id=TURN,tool_name='Bash',tool_use_id='call_fixture_0002')
        self.hook('PostToolUse',turn_id=TURN,tool_name='mcp__babel__list_contacts',tool_use_id='call_fixture_0003')
        self.assertEqual(self.records(),before)
        self.assertNotIn('PRIVATE CONTENT',json.dumps(before))
    def test_claude_final_batches_correlate_once_and_ignore_wake_only(self):
        self.hook(client='claude');self.hook('UserPromptSubmit',client='claude',prompt='Implement the scoped fix.')
        self.hook('MessageDisplay',client='claude',turn_id=TURN,final=False,delta='private text')
        self.hook('MessageDisplay',client='claude',turn_id=TURN,final=True,delta='')
        self.hook('MessageDisplay',client='claude',turn_id=TURN,final=True)
        self.hook('MessageDisplay',client='claude',turn_id=TURN2,final=True)
        records=self.records('claude');self.assertEqual(len(records),2)
        self.assertNotIn('private text',json.dumps(records))
    def test_real_resume_stable_rotation_and_later_turn_use_candidate(self):
        self.hook();before=self.records()[0]['sha256'];self.now+=100
        self.hook(source='resume');self.hook(source='resume')
        self.hook('UserPromptSubmit',turn_id=TURN,prompt='Continue implementing this task.')
        records=self.records();resume=[r for r in records if r['kind']=='resume']
        self.assertEqual(len(resume),1);self.assertNotEqual(resume[0]['sha256'],before)
        self.assertEqual([r for r in records if r['kind']=='turn'][0]['sha256'],resume[0]['sha256'])
    def test_genuine_task_after_idle_rotates_no_timer_needed(self):
        self.hook();self.now+=IDLE_SECONDS+1
        self.hook('UserPromptSubmit',turn_id=TURN,prompt='Resume this implementation.')
        self.assertEqual(len([r for r in self.records() if r['kind']=='resume']),1)
    def test_backward_local_clock_preserves_spool(self):
        self.hook();before=self.records();self.now-=1
        with self.assertRaises(BridgeError):self.hook('UserPromptSubmit',turn_id=TURN,prompt='Fix the bug.')
        self.assertEqual(self.records(),before)
    def test_crash_after_db_commit_recovers_spool_without_new_observation(self):
        with patch.object(self.dispatcher,'flush',side_effect=[None,OSError('synthetic crash')]):
            with self.assertRaises(OSError):self.hook()
        self.now+=100;self.hook()
        self.assertEqual(self.records()[0]['observed_at'],self.now-100)
    def test_private_collector_actual_server_delayed_time_receipts_and_gateway_auth(self):
        self.hook();eventtime=self.now
        servernow=self.now+30;store=Store(':memory:');base=Policy(fixture(servernow));leases=SessionLeases(store,accounts(),clock=lambda:servernow)
        runner=self.runner(store,leases,base);ledger=self.root/'collector.json'
        gateway=None
        try:
            requests=collect('mikkel@pop-os',runner);self.assertEqual(len(requests),1)
            self.assertEqual(apply_pending('mikkel@pop-os',requests,ledger,runner),1)
            self.assertEqual(collect('mikkel@pop-os',runner),[])
            self.assertTrue(self.records()) # receipts preserve evidence
            row=dict(store.db.execute('SELECT * FROM trusted_sessions').fetchone())
            self.assertEqual(row['deadline'],eventtime+IDLE_SECONDS)
            ctx={'client':'codex','native_id':SID};path=self.helper.path(ctx);token=(path/'token').read_text().strip()
            gateway=Gateway(0,base,'https://babel.fixture.test',store=store)
            thread=threading.Thread(target=gateway.serve_forever,daemon=True);thread.start()
            rpc={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'list_contacts','arguments':{}}}
            req=Request('http://127.0.0.1:'+str(gateway.port)+'/mcp/v1',data=json.dumps(rpc).encode(),headers={
                'Host':'babel.fixture.test','X-Forwarded-Proto':'https','Authorization':'Bearer '+token,
                'Content-Type':'application/json','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-11-25'})
            opener=build_opener(ProxyHandler({}))
            payload=json.load(opener.open(req,timeout=3));contacts=json.loads(payload['result']['content'][0]['text'])['contacts']
            self.assertEqual([c['recipient'] for c in contacts],[EMBER])
            servernow=row['deadline']
            with self.assertRaises(HTTPError) as error:opener.open(req,timeout=3)
            self.assertEqual(error.exception.code,401)
        finally:
            if gateway:gateway.shutdown();gateway.server_close()
            store.close()
    def test_stale_future_metadata_rejected_no_public_timestamp(self):
        self.hook();r=self.records()[0];now=self.now+10;store=Store(':memory:');base=Policy(fixture(now));leases=SessionLeases(store,accounts(),clock=lambda:now)
        try:
            for value in (now+1,now-IDLE_SECONDS,float('nan'),True):
                bad=dict(r,observed_at=value)
                with self.assertRaises(BridgeError):apply(store,accounts(),base,'mikkel@pop-os',bad)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM trusted_sessions').fetchone()[0],0)
            bad=dict(r,timestamp=now)
            with self.assertRaises(BridgeError):apply(store,accounts(),base,'mikkel@pop-os',bad)
        finally:store.close()
    def test_exact_reviewed_legacy_binding_uses_old_token_and_spools_for_collector(self):
        parent=self.helper.root.parent;root=parent/'instances';root.mkdir(mode=0o700)
        legacy=root/'codex-existing';legacy.mkdir(mode=0o700)
        save(legacy/'token',TOKENS[MANUAL]+'\n')
        save(legacy/'enrollment.json',json.dumps({'client':'codex','participant':MANUAL,'sha256':sha(TOKENS[MANUAL])}))
        save(parent/'native-bindings.json',json.dumps({'schema_version':1,'bindings':{'codex:'+SID:'existing'}}))
        self.hook()
        self.assertEqual((legacy/'token').read_text().strip(),TOKENS[MANUAL])
        self.assertTrue((legacy/'lifecycle.sqlite3').exists())
        spool=list(self.helper.root.glob('codex-auto_*/lifecycle-events/*.json'))
        self.assertEqual(len(spool),1)
        r=json.loads(spool[0].read_text());self.assertEqual(r['existing_participant'],MANUAL)
        now=self.now+10;store=Store(':memory:');base=Policy(fixture(now));leases=SessionLeases(store,accounts(),clock=lambda:now)
        try:
            leases.adopt(base,peer='mikkel@pop-os',participant=MANUAL,native_id=SID)
            result=apply(store,accounts(),base,'mikkel@pop-os',r)
            self.assertEqual(result['participant'],MANUAL)
            self.assertEqual(len(leases.project(base).conversations),2)
        finally:store.close()
    def test_uncertain_spool_receipt_retry_never_resubmits_activity(self):
        self.hook();now=self.now+10;store=Store(':memory:');base=Policy(fixture(now));leases=SessionLeases(store,accounts(),clock=lambda:now)
        runner=self.runner(store,leases,base);calls=[]
        def broken(argv,**kw):
            if '/usr/local/sbin/agent-babel-trusted-session' in argv:calls.append('server')
            elif 'input' in kw:return SimpleNamespace(returncode=1,stdout='')
            return runner(argv,**kw)
        try:
            requests=collect('mikkel@pop-os',runner);ledger=self.root/'collector.json'
            with self.assertRaises(BridgeError):apply_pending('mikkel@pop-os',requests,ledger,broken)
            self.assertEqual(len(calls),1)
            self.assertEqual(apply_pending('mikkel@pop-os',requests,ledger,runner),0)
            self.assertEqual(collect('mikkel@pop-os',runner),[])
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM trusted_session_evidence').fetchone()[0],1)
        finally:store.close()
    def test_stale_queue_does_not_block_new_real_work_or_renew_from_scan_time(self):
        self.now-=IDLE_SECONDS+10;self.hook();self.now+=IDLE_SECONDS+10
        observed=self.now;self.hook('UserPromptSubmit',turn_id=TURN,prompt='Continue the real task.')
        now=self.now+20;store=Store(':memory:');base=Policy(fixture(now));leases=SessionLeases(store,accounts(),clock=lambda:now)
        runner=self.runner(store,leases,base)
        try:
            requests=collect('mikkel@pop-os',runner)
            self.assertEqual(apply_pending('mikkel@pop-os',requests,self.root/'collector.json',runner),1)
            row=dict(store.db.execute('SELECT * FROM trusted_sessions').fetchone())
            self.assertEqual(row['deadline'],observed+IDLE_SECONDS)
            self.assertEqual(store.db.execute('SELECT COUNT(*) FROM trusted_session_evidence').fetchone()[0],1)
            self.assertEqual(len(self.records()),2)
            self.assertEqual(collect('mikkel@pop-os',runner),[])
        finally:store.close()
    def test_integrated_existing_claude_stream_preserves_routes_and_stops_at_idle(self):
        now=self.now;pid='bits255.claude.existing_01';cfg=fixture(now)
        entry=cfg['participants'].pop(MANUAL);entry.update(client='claude',session='existing_01')
        cfg['participants'][pid]=entry
        for c in cfg['conversations'].values():
            c['participants']=[pid if x==MANUAL else x for x in c['participants']]
            for route in c['routes']:
                for k in ('sender','recipient'):
                    if route[k]==MANUAL:route[k]=pid
        store=Store(':memory:');base=Policy(cfg);store.sync_policy(base);leases=SessionLeases(store,accounts(),clock=lambda:now)
        gateway=None
        try:
            leases.adopt(base,peer='work@pop-os',participant=pid,native_id=SID)
            gateway=Gateway(0,base,'https://babel.fixture.test',store=store,channel_recipients=(pid,))
            policy=gateway.current_policy()
            msg=ScopedStore(store,EMBER,policy.agents[EMBER][1],policy).stage(EMBER,pid,text='Synthetic scoped wake test.',message_id='synthetic-claude-idle-test',conversation_id='manual_ember_chat',provenance='mcp')
            self.assertEqual(len(gateway.approvals.pending(policy,pid)),1)
            deadline=leases.row(pid)['deadline'];now=deadline-1
            gateway.approvals.pending(gateway.current_policy(),pid)
            self.assertEqual(leases.row(pid)['deadline'],deadline)
            now=deadline
            with self.assertRaises(BridgeError):gateway.approvals.pending(gateway.current_policy(),pid)
            self.assertEqual(store._row(msg['message']['id'])['status'],'queued')
            self.assertEqual(store._row(msg['message']['id'])['acknowledged'],None)
        finally:
            if gateway:gateway.server_close()
            store.close()
