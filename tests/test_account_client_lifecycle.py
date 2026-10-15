"""Existing local lifecycle contracts, independent of private server code."""
import json
import unittest
from unittest.mock import patch
from babel.core import BridgeError
from babel.native_lifecycle import parse
from tests.account_client_fixture import DispatcherTests, SID, TURN, TURN2

IDLE_SECONDS=86400

class AccountClientLifecycleTests(DispatcherTests,unittest.TestCase):
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
