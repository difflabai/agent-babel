"""Fast prompt behavior with synthetic local accounts, never live enrollment."""
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from babel import prompt_intake
from account_lifecycle_hook import Dispatcher
from tests import account_client_fixture as lifecycle
from tests.account_client_fixture import SID

TURN = lifecycle.TURN
TURN2 = lifecycle.TURN2


class FastPromptTests(unittest.TestCase):
    setUp = lifecycle.DispatcherTests.setUp
    tearDown = lifecycle.DispatcherTests.tearDown
    hook = lifecycle.DispatcherTests.hook
    records = lifecycle.DispatcherTests.records

    def prompt(self, text='Implement the scoped change.', **kwargs):
        return self.hook('UserPromptSubmit', client='claude', prompt=text, **kwargs)

    def finish(self, turn=TURN):
        return self.hook('MessageDisplay', client='claude', turn_id=turn, final=True)

    def journal(self):
        return Path(prompt_intake.location(self.helper.root, self.helper.peer, SID)[1])

    def test_prompt_avoids_lifecycle_lock_database_flush_and_credential_path(self):
        self.hook(client='claude')
        native=self.helper.path({'client':'claude','native_id':SID,'kind':'bootstrap','event_id':'bootstrap:'+SID})
        with open(native/'lifecycle.lock','a') as lock, open(native/'lock','a') as credential_lock:
            fcntl.flock(lock,fcntl.LOCK_EX);fcntl.flock(credential_lock,fcntl.LOCK_EX)
            db=sqlite3.connect(native/'lifecycle.sqlite3');db.execute('BEGIN EXCLUSIVE')
            try:
                with patch.object(self.dispatcher,'flush',side_effect=AssertionError('history replay on prompt')), patch.object(self.helper,'prepare',side_effect=AssertionError('credentials on prompt')):
                    before=time.monotonic();result=self.prompt('PRIVATE PROMPT MUST NEVER BE STORED')
                    self.assertLess(time.monotonic()-before,0.25)
                    self.assertEqual(result['status'],'tracked');self.assertFalse(result['activity_queued'])
            finally:db.rollback();db.close()
        data=''.join(p.read_text() for p in self.journal().glob('*.json'))
        self.assertNotIn('PRIVATE PROMPT',data)
        self.assertEqual(len(self.records('claude')),1)
        self.finish();self.assertEqual(len(self.records('claude')),2)

    def test_latest_prompt_wins_and_notifications_never_borrow_work(self):
        self.hook(client='claude');self.prompt();self.prompt('Babel mailbox notification for this participant')
        self.finish();self.assertEqual(len(self.records('claude')),1)
        self.prompt();self.finish(TURN2)
        self.finish(TURN2);self.assertEqual(len(self.records('claude')),2)

    def test_repeated_prompts_without_completion_are_coalesced_and_bounded(self):
        self.hook(client='claude')
        for _ in range(200):self.prompt()
        self.assertEqual(len(list(self.journal().glob('*.json'))),1)
        self.finish();self.assertEqual(len(self.records('claude')),2)

    def test_repeated_explicit_turns_are_deduplicated_and_completion_once(self):
        self.hook(client='claude')
        for _ in range(20):self.prompt(turn_id=TURN.upper())
        self.finish();self.finish()
        self.assertEqual(len(self.records('claude')),2)
        self.assertFalse(list(self.journal().glob('*.json')))

    def test_concurrent_submissions_and_late_old_prompt_preserve_correlation(self):
        self.hook(client='claude');errors=[]
        def write(index):
            try:self.prompt('Implement item '+str(index),turn_id=f'10000000-0000-4000-8000-{index:012d}')
            except Exception as e:errors.append(e)
        threads=[threading.Thread(target=write,args=(n,)) for n in range(1,25)]
        for t in threads:t.start()
        for t in threads:t.join(3);self.assertFalse(t.is_alive())
        self.assertEqual(errors,[])
        self.finish('10000000-0000-4000-8000-000000000024')
        self.assertEqual(len(self.records('claude')),2)
        # A record published late, but observed before the completed final,
        # cannot lend eligibility to an unrelated later completion.
        old=[int(self.now*1e9),1]
        item=prompt_intake.parse_prompt({'session_id':SID,'prompt':'Old real prompt'},env={})
        prompt_intake.record(self.helper.root,self.helper.peer,item,old)
        self.finish('20000000-0000-4000-8000-000000000999')
        self.assertEqual(len(self.records('claude')),2)

    def test_future_prompt_is_not_consumed_by_an_older_completion(self):
        self.hook(client='claude')
        item=prompt_intake.parse_prompt({'session_id':SID,'prompt':'Next real task'},env={})
        prompt_intake.record(self.helper.root,self.helper.peer,item,[int((self.now+10)*1e9),1])
        self.finish();self.assertEqual(len(self.records('claude')),1)
        self.now+=20;self.finish(TURN2)
        self.assertEqual(len(self.records('claude')),2)

    def test_spool_or_prepare_failure_retains_eligibility_for_retry(self):
        self.hook(client='claude');self.prompt()
        with patch.object(self.dispatcher,'flush',side_effect=OSError('synthetic unavailable service/spool')):
            with self.assertRaises(OSError):self.finish()
        self.finish();self.assertEqual(len(self.records('claude')),2)
        self.prompt(turn_id=TURN2)
        with patch.object(self.helper,'prepare',side_effect=OSError('synthetic helper lock/transport failure')):
            with self.assertRaises(OSError):self.finish(TURN2)
        self.finish(TURN2);self.assertEqual(len(self.records('claude')),3)

    def test_backlog_capacity_fails_closed_without_lending_old_prompt(self):
        self.hook(client='claude')
        with patch.object(prompt_intake,'MAX_PENDING',2):
            self.prompt(turn_id=TURN);self.prompt(turn_id=TURN2)
            with self.assertRaises(ValueError):self.prompt('Babel mailbox notification')
        self.assertTrue((self.journal()/'overflow').is_file())
        self.finish();self.assertEqual(len(self.records('claude')),1)
        self.assertFalse((self.journal()/'overflow').exists())
        self.prompt();self.finish(TURN2);self.assertEqual(len(self.records('claude')),2)

    def test_owner_hosted_subagent_and_symlink_checks_are_preserved(self):
        self.hook(client='claude')
        with self.assertRaises(ValueError):prompt_intake.parse_prompt({'session_id':SID,'prompt':'real'},env={'CLAUDE_CODE_REMOTE':'true'})
        self.assertIsNone(prompt_intake.parse_prompt({'session_id':SID,'agent_id':'child','prompt':'real'},env={}))
        item=prompt_intake.parse_prompt({'session_id':SID,'prompt':'real'},env={})
        with self.assertRaises(ValueError):prompt_intake.record(self.helper.root,'unapproved@pop-os',item,prompt_intake.observation())
        folder=self.journal();folder.mkdir(mode=0o700,parents=True,exist_ok=True)
        target=self.root/'unrelated';target.mkdir();bad=folder/'bad.json';bad.symlink_to(target/'data')
        with self.assertRaises(ValueError):self.finish()
        self.assertFalse((target/'data').exists())

    def test_cli_imports_no_sqlite_network_or_credential_helper(self):
        account=self.helper.root.parent/'test-account.json';account.write_text(json.dumps({'schema_version':1,'peer':'mikkel@pop-os'}));account.chmod(0o600)
        script='''import runpy,sys,pwd
from types import SimpleNamespace
pwd.getpwuid=lambda uid:SimpleNamespace(pw_name='mikkel')
blocked=('sqlite3','socket','urllib','account_session_helper','babel.core','babel.lifecycle_dispatcher')
def audit(event,args):
 if event=='import' and any(args[0]==name or args[0].startswith(name+'.') for name in blocked):
  raise AssertionError('slow module imported: '+args[0])
sys.addaudithook(audit)
sys.argv=['account_lifecycle_hook.py','--client','claude','--account-file',sys.argv[1]]
runpy.run_path('account_lifecycle_hook.py',run_name='__main__')
'''
        result=subprocess.run([sys.executable,'-c',script,str(account)],input=json.dumps({'hook_event_name':'UserPromptSubmit','session_id':SID,'prompt':'Implement the test.'}),text=True,capture_output=True,timeout=2)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('hookSpecificOutput',json.loads(result.stdout))
        # Prompt intake alone never creates enrollment, a token or lifecycle DB.
        self.assertFalse(list(self.helper.root.rglob('token')))
        self.assertFalse(list(self.helper.root.rglob('lifecycle.sqlite3')))

    def test_cli_is_fast_when_an_existing_lifecycle_lock_is_held(self):
        self.hook(client='claude')
        account=self.helper.root.parent/'test-account.json';account.write_text(json.dumps({'schema_version':1,'peer':'mikkel@pop-os'}));account.chmod(0o600)
        path=self.helper.path({'client':'claude','native_id':SID,'kind':'bootstrap','event_id':'bootstrap:'+SID})
        with open(path/'lifecycle.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            started=time.monotonic()
            for _ in range(5):
                r=subprocess.run(lifecycle.cli_command('account_lifecycle_hook.py',account),input=json.dumps({'hook_event_name':'UserPromptSubmit','session_id':SID,'prompt':'Implement the test.'}),text=True,capture_output=True,timeout=1)
                self.assertEqual(r.returncode,0,r.stderr);json.loads(r.stdout)
            self.assertLess(time.monotonic()-started,1)
        self.now=time.time()+1
        self.finish();self.assertEqual(len(self.records('claude')),2)

    def test_interrupted_prompt_cannot_lend_an_earlier_meaningful_prompt(self):
        self.hook(client='claude');self.prompt()
        replace=prompt_intake.os.replace
        def broken(source,target):
            if str(target).endswith('.json'):raise OSError('synthetic storage failure')
            return replace(source,target)
        with patch('babel.prompt_intake.os.replace',side_effect=broken):
            with self.assertRaises(OSError):self.prompt('Babel mailbox notification')
        self.finish();self.assertEqual(len(self.records('claude')),1)
        self.assertFalse(list(self.journal().glob('failed-*')))
        self.prompt();self.finish(TURN2);self.assertEqual(len(self.records('claude')),2)

    def test_crashed_intake_is_invalidated_once_and_new_work_can_continue(self):
        self.hook(client='claude');self.prompt()
        stamp=prompt_intake.observation(lambda:self.now)
        failed=self.journal()/('.pending-'+str(stamp[0]).zfill(21)+'-'+str(stamp[1]).zfill(21)+'-b'+prompt_intake.boot_id().replace('-','')+'-synthetic')
        failed.write_text('partial metadata');failed.chmod(0o600)
        self.finish();self.assertEqual(len(self.records('claude')),1)
        self.assertFalse(failed.exists())
        self.prompt();self.finish(TURN2);self.assertEqual(len(self.records('claude')),2)

    def test_reviewed_legacy_binding_keeps_credential_location_and_prompt_is_local(self):
        import hashlib
        parent=self.helper.root.parent;instances=parent/'instances';instances.mkdir(mode=0o700)
        legacy=instances/'claude-existing';legacy.mkdir(mode=0o700)
        token='synthetic-private-existing-credential-000000000000'
        (legacy/'token').write_text(token);(legacy/'token').chmod(0o600)
        old={'client':'claude','participant':'bits255.claude.existing_01','sha256':hashlib.sha256(token.encode()).hexdigest()}
        (legacy/'enrollment.json').write_text(json.dumps(old));(legacy/'enrollment.json').chmod(0o600)
        (parent/'native-bindings.json').write_text(json.dumps({'schema_version':1,'bindings':{'claude:'+SID:'existing'}}));(parent/'native-bindings.json').chmod(0o600)
        self.hook(client='claude')
        with patch.object(self.helper,'prepare',side_effect=AssertionError('prepare on prompt')):
            self.prompt()
        self.finish()
        self.assertEqual((legacy/'token').read_text(),token)
        db=sqlite3.connect(legacy/'lifecycle.sqlite3')
        try:self.assertEqual(db.execute('SELECT finished FROM turns WHERE id=?',(TURN,)).fetchone(),(1,))
        finally:db.close()
        records=[json.loads(p.read_text()) for p in (self.journal().parent/'lifecycle-events').glob('*.json')]
        self.assertEqual(len(records),2)
        self.assertTrue(all(r['existing_participant']=='bits255.claude.existing_01' for r in records))

    def test_explicit_id_retry_at_capacity_does_not_invalidate_eligibility(self):
        self.hook(client='claude')
        with patch.object(prompt_intake,'MAX_PENDING',1):
            self.prompt(turn_id=TURN);self.prompt('status check',turn_id=TURN)
        self.assertFalse((self.journal()/'overflow').exists())
        self.finish();self.assertEqual(len(self.records('claude')),2)

    def test_cleanup_crash_after_sql_commit_replays_without_duplicate_activity(self):
        self.hook(client='claude');self.prompt()
        with patch.object(prompt_intake,'remove',side_effect=OSError('synthetic cleanup crash')):
            with self.assertRaises(OSError):self.finish()
        self.assertTrue(list(self.journal().glob('*.json')))
        self.finish();self.finish();self.assertEqual(len(self.records('claude')),2)

    def test_concurrently_coalesced_record_does_not_abort_completion(self):
        self.hook(client='claude');self.prompt()
        target=next(self.journal().glob('*.json'));check=prompt_intake.private
        def vanished(path,directory=False):
            if os.fspath(path)==str(target) and target.exists():target.unlink()
            return check(path,directory)
        with patch.object(prompt_intake,'private',side_effect=vanished):self.finish()
        self.assertEqual(len(self.records('claude')),1)
        self.prompt();self.finish(TURN2);self.assertEqual(len(self.records('claude')),2)

    def test_prompt_has_no_synchronous_disk_barrier(self):
        self.hook(client='claude')
        with patch('babel.prompt_intake.os.fsync',side_effect=AssertionError('prompt must not flush disk')):
            self.prompt()
        self.finish();self.assertEqual(len(self.records('claude')),2)

    def test_reboot_drops_uncommitted_prompt_without_renewing_or_losing_history(self):
        self.hook(client='claude');self.prompt();self.finish()
        self.prompt(turn_id=TURN2)
        with patch.object(prompt_intake,'boot_id',return_value='30000000-0000-4000-8000-000000000001'):
            self.finish(TURN2)
            self.assertEqual(len(self.records('claude')),2)
            self.prompt(turn_id='10000000-0000-4000-8000-000000000099')
            self.finish('10000000-0000-4000-8000-000000000099')
        self.assertEqual(len(self.records('claude')),3)

    def test_lost_notification_after_reboot_cannot_borrow_sqlite_pending_prompt(self):
        self.hook(client='claude');self.prompt()
        ctx={'client':'claude','native_id':SID,'kind':'bootstrap','event_id':'bootstrap:'+SID}
        path=self.helper.path(ctx);db=sqlite3.connect(path/'lifecycle.sqlite3')
        try:
            self.dispatcher.consume_prompts(db,ctx,prompt_intake.observation(lambda:self.now))
            self.assertEqual(db.execute("SELECT meaningful FROM turns WHERE id='claude-pending'").fetchone(),(1,))
        finally:db.close()
        with patch.object(prompt_intake,'boot_id',return_value='30000000-0000-4000-8000-000000000001'):
            self.finish()
        self.assertEqual(len(self.records('claude')),1)
