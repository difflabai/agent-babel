"""Owned synthetic lifecycle evidence; no real SSH, tokens, native activity or server."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from babel import account_enrollment as enroll
from babel.account_bootstrap import local_key
from babel.core import BridgeError
from babel.native_lifecycle import event_key


class AccountEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name);self.home.chmod(0o700)
        self.root=self.home/'.config/255bits/agent-babel';self.root.mkdir(mode=0o700,parents=True)
        self.account=self.root/'trusted-account.json'
        self.write(self.account,{'schema_version':1,'peer':'mikkel@pop-os'})
        self.who=patch.object(enroll.pwd,'getpwuid',return_value=SimpleNamespace(pw_name='mikkel',pw_dir=str(self.home)))
        self.who.start();self.addCleanup(self.who.stop)
        self.host=patch.object(enroll.socket,'gethostname',return_value='pop-os');self.host.start();self.addCleanup(self.host.stop)
        self.now=time.time()-2
        self.calls=[]
        self.transport=Mock();self.transport.submit.side_effect=self.accept
        self.counter=0

    def write(self,path,value):
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        for parent in path.parents:
            if parent==self.home:break
            parent.chmod(0o700)
        path.write_text(json.dumps(value));path.chmod(0o600)

    def enabled(self,value=True):
        self.write(self.root/enroll.TRANSPORT_FILE,{'schema_version':1,'enabled':value,'transport':'pinned-ssh-operator'})
        return enroll.Configuration(self.account)

    def event(self,index=1,*,kind='bootstrap',client='codex',observed=None,sha=None,event_id=None):
        sid='ses_synthetic'+str(index).zfill(16) if client=='opencode' else '20000000-0000-4000-8000-'+str(index).zfill(12)
        self.counter+=1
        eid=event_id or ('bootstrap:'+sid if kind=='bootstrap' else event_key(sid,kind,self.counter))
        request={'schema_version':2,'client':client,'native_id':sid,'sha256':sha or hashlib.sha256(('synthetic-'+sid).encode()).hexdigest(),
                 'kind':kind,'event_id':eid,'observed_at':self.now-10 if observed is None else observed}
        folder=client+'-auto_'+local_key('mikkel@pop-os',request)
        path=self.root/'automatic-instances'/folder/'lifecycle-events'/(event_key(eid)[7:]+'.json')
        self.write(path,request)
        return path,request

    def reply(self,request):
        key=local_key('mikkel@pop-os',request)
        return {'participant':'bits255.'+request['client']+'.auto_'+key,'conversation':'report_auto_'+key+'_ember',
                'generation':1,'state':'active','deadline':self.now+86400}

    def accept(self,peer,request,**kwargs):
        self.assertEqual(peer,'mikkel@pop-os');self.calls.append(copy.deepcopy(request))
        return self.reply(request)

    def drain(self):
        return enroll.Drainer(enroll.Configuration(self.account),transport=self.transport,clock=lambda:self.now).run()

    def test_disabled_and_absent_config_do_not_write_spawn_or_submit(self):
        before=set(self.root.iterdir())
        with patch.object(enroll.subprocess,'Popen') as spawn:
            self.assertFalse(enroll.ensure_enrollment(self.account))
            spawn.assert_not_called()
        self.assertEqual(set(self.root.iterdir()),before)
        config=self.enabled(False)
        self.assertEqual(enroll.Drainer(config,transport=self.transport).run(),{'state':'disabled'})
        self.assertFalse(config.state.exists());self.transport.submit.assert_not_called()

    def test_real_uid_hostname_canonical_path_and_private_optin_are_mandatory(self):
        self.enabled()
        with patch.object(enroll.socket,'gethostname',return_value='elsewhere'):
            self.assertFalse(enroll.ensure_enrollment(self.account))
        with patch.object(enroll.pwd,'getpwuid',return_value=SimpleNamespace(pw_name='work',pw_dir=str(self.home))):
            self.assertFalse(enroll.ensure_enrollment(self.account))
        self.assertFalse(enroll.ensure_enrollment(self.home/'foreign-account.json'))
        config=self.root/enroll.TRANSPORT_FILE;config.chmod(0o644)
        self.assertFalse(enroll.ensure_enrollment(self.account));config.chmod(0o600)
        copy_path=self.root/'saved-transport.json';config.rename(copy_path);config.symlink_to(copy_path)
        self.assertFalse(enroll.ensure_enrollment(self.account))
        self.assertFalse((self.root/enroll.STATE_DIRECTORY).exists())

    def test_unknown_transport_fields_cannot_supply_command_peer_or_key(self):
        for extra in ('peer','command','host','identity_file'):
            data={'schema_version':1,'enabled':True,'transport':'pinned-ssh-operator',extra:'untrusted'}
            self.write(self.root/enroll.TRANSPORT_FILE,data)
            self.assertFalse(enroll.ensure_enrollment(self.account))

    def test_fresh_owned_evidence_acceptance_and_receipts_are_exact_and_idempotent(self):
        self.enabled();path,request=self.event(client='opencode')
        token=path.parent.parent/'token';token.write_text('SENSITIVE-NEVER-READ');token.chmod(0o600)
        original=enroll.read_bytes
        def no_credentials(p,*args,**kwargs):
            self.assertNotIn(Path(p).name,('token','resume-token','transcript.json'))
            return original(p,*args,**kwargs)
        with patch.object(enroll,'read_bytes',side_effect=no_credentials):
            result=self.drain();again=self.drain()
        self.assertEqual(result['accepted'],1);self.assertEqual(again['accepted'],0)
        self.assertEqual(self.calls,[request]);self.assertEqual(enroll.read_json(path),request)
        self.assertEqual(path.with_suffix('.receipt').read_text(),enroll.digest(request)+'\n')
        self.assertEqual(token.read_text(),'SENSITIVE-NEVER-READ')

    def test_invalid_foreign_future_legacy_schema_and_unobserved_requests_never_submit(self):
        self.enabled()
        for index in range(1,7):
            path,r=self.event(index)
            if index==1:r.pop('observed_at')
            if index==2:r['schema_version']=1
            if index==3:r['observed_at']=self.now+1
            if index==4:r['existing_participant']='bits255.codex.old_worker'
            if index==5:r['unexpected']='SENSITIVE-NOT-FORWARDED'
            if index==6:r['native_id']='foreign-context'
            self.write(path,r)
        result=self.drain();self.assertEqual(result['accepted'],0)
        self.transport.submit.assert_not_called()
        self.assertFalse(list(self.root.rglob('*.receipt')))

    def test_no_trusted_manifest_fallback_or_bare_turn_enrollment(self):
        self.enabled();path,r=self.event(kind='turn')
        self.write(path.parent.parent/'trusted-enrollment.json',{k:v for k,v in r.items() if k!='observed_at'})
        self.drain();self.transport.submit.assert_not_called()
        self.assertFalse(path.with_suffix('.receipt').exists())

    def test_stale_evidence_is_retained_without_fabricated_acceptance_or_freshness(self):
        self.enabled();path,r=self.event(observed=self.now-86400)
        self.drain();self.transport.submit.assert_not_called()
        self.assertEqual(enroll.read_json(path),r);self.assertFalse(path.with_suffix('.receipt').exists())
        resume,new=self.event(kind='resume',observed=self.now-1,sha='a'*64)
        self.drain();self.assertEqual(self.calls,[new]);self.assertTrue(resume.with_suffix('.receipt').exists())
        self.assertFalse(path.with_suffix('.receipt').exists())

    def test_wrong_or_malformed_success_is_not_an_ack_and_does_not_block_other_sessions(self):
        self.enabled();one,r1=self.event(1);two,r2=self.event(2,client='opencode')
        def response(peer,r,**kwargs):
            self.calls.append(copy.deepcopy(r))
            return {'queued':True} if r['client']=='codex' else self.reply(r)
        self.transport.submit.side_effect=response
        self.drain();self.assertFalse(one.with_suffix('.receipt').exists());self.assertTrue(two.with_suffix('.receipt').exists())
        for mutation in ({'state':'idle_expired'},{'generation':True},{'deadline':self.now},{'participant':'wrong'},{'conversation':'wrong'}):
            reply=self.reply(r1);reply.update(mutation)
            with self.assertRaises(enroll.OperatorRejected):enroll.accepted_reply('mikkel@pop-os',r1,reply,self.now)

    def test_application_denial_only_backs_off_that_session(self):
        self.enabled();failed,r1=self.event(1,client='grokbot');self.event(1,client='grokbot',kind='turn',observed=self.now-5)
        good,r2=self.event(2,client='opencode')
        def submit(peer,r,**kwargs):
            self.calls.append(copy.deepcopy(r))
            if r['client']=='grokbot':raise enroll.OperatorRejected('private details must stay local')
            return self.reply(r)
        self.transport.submit.side_effect=submit
        self.drain();self.drain()
        self.assertEqual(len(self.calls),2);self.assertTrue(good.with_suffix('.receipt').exists())
        self.assertFalse(failed.with_suffix('.receipt').exists())
        self.assertNotIn('turn',[r['kind'] for r in self.calls])

    def test_bootstrap_turn_and_rotation_order_is_preserved(self):
        self.enabled()
        events=[self.event(observed=self.now-40),self.event(kind='turn',observed=self.now-30),
                self.event(kind='resume',observed=self.now-20,sha='a'*64),self.event(kind='turn',observed=self.now-10,sha='a'*64)]
        self.drain()
        self.assertEqual(self.calls,[r for _,r in events])

    def test_ambiguous_transport_retries_identical_ids_payload_and_honors_global_backoff(self):
        config=self.enabled();path,r=self.event()
        def uncertain(peer,request,**kwargs):
            self.calls.append(copy.deepcopy(request));raise enroll.TransportUnavailable('connection lost after acceptance')
        self.transport.submit.side_effect=uncertain
        self.drain();self.drain();self.assertEqual(self.calls,[r]);self.assertFalse(path.with_suffix('.receipt').exists())
        with patch.object(enroll.time,'time',return_value=self.now),patch.object(enroll.subprocess,'Popen') as spawn:
            self.assertFalse(enroll.ensure_enrollment(self.account,fresh=True));spawn.assert_not_called()
        self.now+=21;self.transport.submit.side_effect=self.accept;self.drain()
        self.assertEqual(self.calls,[r,r]);self.assertTrue(path.with_suffix('.receipt').exists())

    def test_verified_acceptance_recovers_receipt_after_crash_without_resubmission(self):
        self.enabled();path,r=self.event()
        with patch.object(enroll,'receipt',side_effect=OSError('simulated disk interruption')):
            self.drain()
        self.assertFalse(path.with_suffix('.receipt').exists())
        self.drain();self.assertEqual(self.calls,[r]);self.assertTrue(path.with_suffix('.receipt').exists())

    def test_owner_optout_during_inflight_submission_stops_later_network_calls(self):
        self.enabled();self.event(1);self.event(2)
        def submit(peer,r,**kwargs):
            self.calls.append(copy.deepcopy(r));self.enabled(False);return self.reply(r)
        self.transport.submit.side_effect=submit
        self.drain();self.assertEqual(len(self.calls),1);self.assertEqual(len(list(self.root.rglob('*.receipt'))),1)

    def test_mutated_ambiguous_event_is_never_forwarded_as_a_new_event(self):
        self.enabled();path,r=self.event()
        self.transport.submit.side_effect=enroll.OperatorRejected
        self.drain();self.transport.submit.reset_mock()
        changed=dict(r,sha256='a'*64);self.write(path,changed)
        self.now+=21;self.drain();self.transport.submit.assert_not_called()
        self.assertFalse(path.with_suffix('.receipt').exists())

    def test_full_ledger_allows_existing_pending_reconciliation(self):
        self.enabled();path,r=self.event()
        self.transport.submit.side_effect=enroll.TransportUnavailable
        with patch.object(enroll,'MAX_RECORDS',1):
            self.drain();self.now+=21;self.transport.submit.side_effect=self.accept;self.drain()
        self.assertTrue(path.with_suffix('.receipt').exists());self.assertEqual(self.calls,[r])

    def test_private_ledger_hardlink_is_rejected_before_sqlite_writes(self):
        config=self.enabled();config.prepare_state()
        original=config.state/'unrelated.sqlite3';original.write_bytes(b'unchanged');original.chmod(0o600)
        os.link(original,config.state/'ledger.sqlite3')
        with self.assertRaises(BridgeError):self.drain()
        self.assertEqual(original.read_bytes(),b'unchanged');self.transport.submit.assert_not_called()

    def test_fifth_busy_session_gets_a_turn_on_the_second_pass(self):
        self.enabled();events=[self.event(index) for index in range(1,enroll.BATCH+2)]
        self.drain();self.now+=21
        for path,r in events:
            if path.with_suffix('.receipt').exists():
                self.event(int(r['native_id'][-12:]),kind='turn',observed=self.now-1)
        self.drain()
        self.assertTrue(all(path.with_suffix('.receipt').exists() for path,_ in events))

    def test_equal_observation_time_orders_resume_before_its_new_digest_turn(self):
        self.enabled();path,bootstrap=self.event(observed=self.now-2)
        self.drain();self.calls.clear()
        _,turn=self.event(kind='turn',sha='a'*64,observed=self.now-1,event_id='aaa-first-turn')
        _,resume=self.event(kind='resume',sha='a'*64,observed=self.now-1,event_id='zzz-last-resume')
        self.drain();self.assertEqual(self.calls,[resume,turn])

    def test_ready_groups_are_not_skipped_when_more_than_scan_or_batch_capacity(self):
        self.enabled();events=[self.event(index) for index in range(1,enroll.SCAN_FOLDERS+5)]
        # Producers that were served first keep making work. Unserved sessions
        # must still get a first acceptance without waiting for a whole wrap.
        # Half the fixed batch is reserved for recent intake and half for the
        # independent round-robin queue, so even hot recent producers cannot
        # starve historical ready groups.
        for _ in range(len(events)//(enroll.BATCH//2)+2):
            self.drain();self.now+=21
            for path,r in events:
                if path.with_suffix('.receipt').exists():
                    self.event(int(r['native_id'][-12:]),kind='turn',observed=self.now-1)
        self.assertEqual(len({r['native_id'] for r in self.calls}),len(events))
        self.assertTrue(all(path.with_suffix('.receipt').exists() for path,_ in events))

    def test_recent_new_session_is_prioritized_among_receipted_history_without_inventing_activity(self):
        self.enabled()
        for index in range(1,101):
            path,r=self.event(index);enroll.receipt(path,r)
            os.utime(path.parent,(self.now-1000,self.now-1000))
        new,r=self.event(1001);self.drain()
        self.assertTrue(new.with_suffix('.receipt').exists());self.assertEqual(self.calls,[r])

    def test_hot_recent_high_folders_cannot_reset_round_robin_past_middle_work(self):
        self.enabled()
        events=sorted([self.event(index) for index in range(1,101)],key=lambda x:x[0].parent.parent.name)
        target,_=events[40];hot=events[-8:]
        for path,r in events:
            if path!=target:enroll.receipt(path,r)
            os.utime(path.parent,(self.now-1000,self.now-1000))
        for _ in range(8):
            for path,r in hot:
                self.event(int(r['native_id'][-12:]),kind='turn',observed=self.now-1)
            self.drain();self.now+=21
            if target.with_suffix('.receipt').exists():break
        self.assertTrue(target.with_suffix('.receipt').exists())

    def test_singleton_scheduler_uses_inherited_lock_and_no_owner_secret_environment(self):
        config=self.enabled()
        def inspect_spawn(argv,**kwargs):
            self.assertEqual(argv[0],sys.executable);self.assertEqual(len(kwargs['pass_fds']),1)
            other=os.open(config.state/'run.lock',os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(other)
            self.assertNotIn('BABEL_SESSION_TOKEN',kwargs['env']);self.assertEqual(kwargs['stdin'],enroll.subprocess.DEVNULL)
            return Mock()
        with patch.dict(os.environ,{'BABEL_SESSION_TOKEN':'SENSITIVE','XAI_API_KEY':'PRIVATE'}),patch.object(enroll.subprocess,'Popen',side_effect=inspect_spawn) as spawn:
            self.assertTrue(enroll.ensure_enrollment(self.account));spawn.assert_called_once()
        fd=os.open(config.state/'run.lock',os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX)
        try:
            with patch.object(enroll.subprocess,'Popen') as spawn:
                self.assertTrue(enroll.ensure_enrollment(self.account));spawn.assert_not_called()
        finally:os.close(fd)

    def test_transport_arguments_are_fixed_and_request_is_metadata_json_stdin_only(self):
        _,r=self.event()
        with patch.dict(os.environ,{'BABEL_SESSION_TOKEN':'SENSITIVE','OPENAI_API_KEY':'PRIVATE'}),patch.object(enroll,'bounded_process',return_value=json.dumps(self.reply(r)).encode()) as run:
            result=enroll.SSHTransport(self.home).submit('mikkel@pop-os',r)
        argv,stdin=run.call_args.args
        self.assertEqual(argv[-3:],['root@159.195.17.119','/usr/local/sbin/agent-babel-trusted-session','mikkel@pop-os'])
        self.assertIn('StrictHostKeyChecking=yes',argv);self.assertEqual(argv[1:3],['-F','/dev/null'])
        self.assertEqual(json.loads(stdin),r);self.assertNotIn('SENSITIVE',str(run.call_args))
        self.assertNotIn('OPENAI_API_KEY',run.call_args.kwargs['env']);self.assertEqual(result,self.reply(r))

    def test_metadata_symlinks_and_hardlinks_are_refused_before_any_submit(self):
        self.enabled();path,r=self.event();saved=path.with_suffix('.saved');path.rename(saved);path.symlink_to(saved)
        self.drain();self.transport.submit.assert_not_called();path.unlink();os.link(saved,path)
        self.drain();self.transport.submit.assert_not_called()

    def test_bounded_transport_never_exposes_private_stderr_or_accepts_oversized_reply(self):
        env={'HOME':str(self.home),'PATH':'/usr/bin:/bin'}
        with self.assertRaises(enroll.OperatorRejected) as error:
            enroll.bounded_process([sys.executable,'-c','import sys;print("PRIVATE"*1000);sys.stderr.write("SECRET")'],b'{}',env=env,timeout=2)
        self.assertNotIn('PRIVATE',str(error.exception));self.assertNotIn('SECRET',str(error.exception))
        with self.assertRaises(enroll.TransportUnavailable):
            enroll.bounded_process([sys.executable,'-c','import time;time.sleep(2)'],b'{}',env=env,timeout=.05)


if __name__=='__main__':unittest.main()
