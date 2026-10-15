"""Code-only package installs and upgrade/recovery in isolated synthetic roots."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import install_account_client as package
from tests.account_client_fixture import cli_command, SID, TURN


class AccountClientInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = self.root / 'client'

    def tearDown(self):
        self.tmp.cleanup()

    def existing(self):
        self.target.mkdir(mode=0o700)
        (self.target / 'babel').mkdir(mode=0o700)
        for name in package.SUPPORT_FILES:
            path = self.target / name
            path.write_bytes((package.SOURCE / name).read_bytes() + b'\n# Existing private bundle support.\n')
            path.chmod(0o600)
        entry = self.target / 'account_lifecycle_hook.py'
        entry.write_text('# Earlier reviewed lifecycle callback.\n')
        entry.chmod(0o700)
        return entry

    def run_hook(self, account, data):
        result = subprocess.run(cli_command(self.target / 'account_lifecycle_hook.py', account),
                                input=json.dumps(data), capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return json.loads(result.stdout)

    def test_dry_run_has_no_writes_and_contains_complete_runtime(self):
        result = package.install(self.target)
        self.assertEqual(result['state'], 'planned')
        self.assertFalse(self.target.exists())
        self.assertEqual(set(result['files']), set(package.CLIENT_FILES + package.SUPPORT_FILES))
        self.assertIn('babel/prompt_intake.py', result['files'])
        self.assertIn('babel/lifecycle_dispatcher.py', result['files'])

    def test_fresh_install_runs_prompt_exit_and_completion_in_separate_processes(self):
        receipt = package.install(self.target, apply=True)
        self.assertEqual(receipt['state'], 'installed')
        self.assertFalse((self.target / 'babel/session_leases.py').exists())
        self.assertFalse((self.target / 'babel/gateway.py').exists())
        # Installation alone never creates runtime identity or settings.
        self.assertFalse(list(self.target.rglob('token')))
        self.assertFalse(list(self.target.rglob('trusted-account.json')))
        state = self.root / 'synthetic-state'
        state.mkdir(mode=0o700)
        account = state / 'trusted-account.json'
        account.write_text(json.dumps({'schema_version': 1, 'peer': 'mikkel@pop-os'}))
        account.chmod(0o600)
        self.run_hook(account, {'hook_event_name': 'SessionStart', 'session_id': SID, 'source': 'startup'})
        self.run_hook(account, {'hook_event_name': 'UserPromptSubmit', 'session_id': SID,
                                'prompt': 'Implement this isolated synthetic change.'})
        events = list(state.rglob('lifecycle-events/*.json'))
        self.assertEqual(len(events), 1)  # Bootstrap only; never manufacture a completion.
        self.assertEqual(len(list(state.rglob('prompt-events/*.json'))), 1)
        final = {'hook_event_name': 'MessageDisplay', 'session_id': SID, 'turn_id': TURN, 'final': True}
        self.run_hook(account, final)
        self.run_hook(account, final)
        self.assertEqual(len(list(state.rglob('lifecycle-events/*.json'))), 2)
        self.assertFalse(list(state.rglob('prompt-events/*.json')))
        for name, sha in receipt['files'].items():
            self.assertEqual(hashlib.sha256((self.target / name).read_bytes()).hexdigest(), sha)

    def test_existing_bundle_requires_adoption_and_preserves_backend_and_state(self):
        entry = self.existing()
        with self.assertRaises(ValueError):
            package.install(self.target, apply=True)
        support = {name: (self.target / name).read_bytes() for name in package.SUPPORT_FILES}
        unrelated = self.target / 'babel/auth.py'
        unrelated.write_text('# Existing policy implementation; never replace.\n')
        unrelated.chmod(0o600)
        credentials = self.target / 'existing-private-state'
        credentials.write_bytes(b'synthetic-existing-state-do-not-replace')
        credentials.chmod(0o600)
        before = entry.read_bytes()
        result = package.install(self.target, apply=True, adopt_existing=True)
        self.assertEqual(entry.stat().st_mode & 0o777, 0o700)
        self.assertEqual((Path(result['backup']) / entry.name).read_bytes(), before)
        for name, raw in support.items():
            self.assertEqual((self.target / name).read_bytes(), raw)
            self.assertNotIn(name, result['files'])
        self.assertEqual(credentials.read_bytes(), b'synthetic-existing-state-do-not-replace')
        self.assertEqual(unrelated.read_text(), '# Existing policy implementation; never replace.\n')

    def test_reinstall_retains_all_managed_fast_path_files_and_refuses_source_drift(self):
        package.install(self.target, apply=True)
        receipt = package.install(self.target, apply=True)
        self.assertEqual(set(receipt['files']), set(package.CLIENT_FILES + package.SUPPORT_FILES))
        file = self.target / 'babel/prompt_intake.py'
        file.write_text(file.read_text() + '\n# Independent local edit.\n')
        changed = file.read_bytes()
        with self.assertRaises(ValueError):
            package.install(self.target, apply=True, adopt_existing=True)
        self.assertEqual(file.read_bytes(), changed)

    def test_interrupted_upgrade_restores_old_entrypoint_and_modules(self):
        entry = self.existing()
        before = entry.read_bytes()
        replace = package.os.replace
        failed = []
        def fail_once(source, target):
            if Path(target) == entry and not failed:
                failed.append(True)
                raise OSError('Synthetic interrupted final entrypoint switch')
            return replace(source, target)
        with patch.object(package.os, 'replace', side_effect=fail_once):
            with self.assertRaises(OSError):
                package.install(self.target, apply=True, adopt_existing=True)
        self.assertEqual(entry.read_bytes(), before)
        self.assertEqual(entry.stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.target / package.RECEIPT).exists())
        self.assertFalse((self.target / 'babel/prompt_intake.py').exists())

    def test_concurrent_installer_fails_without_waiting_or_changing_entrypoint(self):
        entry = self.existing()
        before = entry.read_bytes()
        path = self.target / '.account-client-install.lock'
        with open(path, 'w') as lock:
            path.chmod(0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            with self.assertRaises(BlockingIOError):
                package.install(self.target, apply=True, adopt_existing=True)
        self.assertEqual(entry.read_bytes(), before)

    def test_failed_upgrade_does_not_erase_independent_source_edits(self):
        entry = self.existing()
        before = entry.read_bytes()
        first = self.target / package.CLIENT_FILES[0]
        replace = package.os.replace
        def edit_then_fail(source, target):
            if Path(target) == entry:
                first.write_text('# Independent source edit during installation.\n')
                raise OSError('Synthetic installation failure')
            return replace(source, target)
        with patch.object(package.os, 'replace', side_effect=edit_then_fail):
            with self.assertRaisesRegex(ValueError, 'independently changed source'):
                package.install(self.target, apply=True, adopt_existing=True)
        self.assertEqual(first.read_text(), '# Independent source edit during installation.\n')
        self.assertEqual(entry.read_bytes(), before)

    def test_source_change_between_plan_and_snapshot_is_preserved(self):
        entry = self.existing()
        plan = package.plan
        def concurrent_edit(*args, **kwargs):
            result = plan(*args, **kwargs)
            entry.write_text('# Independent edit after validation.\n')
            return result
        with patch.object(package, 'plan', side_effect=concurrent_edit):
            with self.assertRaisesRegex(ValueError, 'before snapshot'):
                package.install(self.target, apply=True, adopt_existing=True)
        self.assertEqual(entry.read_text(), '# Independent edit after validation.\n')
        self.assertFalse((self.target / 'babel/prompt_intake.py').exists())

    def test_symlink_or_foreign_owned_destinations_are_rejected(self):
        real = self.root / 'real'
        real.mkdir(mode=0o700)
        self.target.symlink_to(real, target_is_directory=True)
        with self.assertRaises(ValueError):
            package.install(self.target, apply=True)
        self.target.unlink()
        self.target.mkdir(mode=0o700)
        with patch.object(package.os, 'getuid', return_value=os.getuid() + 1):
            with self.assertRaises(ValueError):
                package.install(self.target, apply=True)
        (self.target / 'babel').mkdir(mode=0o700)
        (self.target / 'babel/prompt_intake.py').symlink_to(real / 'untouched')
        with self.assertRaises(ValueError):
            package.install(self.target, apply=True)
        self.assertFalse((real / 'untouched').exists())

    def test_missing_release_module_cannot_produce_partial_installation(self):
        source = self.root / 'incomplete-source'
        source.mkdir()
        for name in package.SUPPORT_FILES + package.CLIENT_FILES:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(package.SOURCE / name, path)
        (source / 'babel/prompt_intake.py').unlink()
        with patch.object(package, 'SOURCE', source):
            with self.assertRaises(ValueError):
                package.install(self.target, apply=True)
        self.assertFalse((self.target / 'account_lifecycle_hook.py').exists())
