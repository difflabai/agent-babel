"""Session lookup must work without filesystem write permission or enrollment."""
import contextlib
import errno
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import account_session_helper as helper
from babel.core import BridgeError


class ReadOnlySessionPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.base.chmod(0o700)
        self.root=self.base/'automatic-instances'
        self.ctx={'client':'codex','native_id':'20000000-0000-4000-8000-000000000001',
                  'kind':'bootstrap','event_id':'bootstrap:20000000-0000-4000-8000-000000000001'}
        self.who=patch.object(helper.pwd,'getpwuid',return_value=SimpleNamespace(pw_name='mikkel'))
        self.who.start();self.addCleanup(self.who.stop)

    def reader(self):
        return helper.Helper(self.root,'mikkel@pop-os',token_factory=lambda:'s'*64)

    def test_missing_root_never_attempts_a_write_or_network_call(self):
        with patch.object(Path,'mkdir',side_effect=OSError(errno.EROFS,'read-only')) as mkdir, \
             patch.object(helper.Helper,'call') as network:
            reader=self.reader()
            with self.assertRaises(helper.SessionNotPrepared) as error:reader.path(self.ctx)
        self.assertEqual(error.exception.status,409)
        mkdir.assert_not_called();network.assert_not_called()
        self.assertFalse(self.root.exists())

    def test_missing_session_in_existing_root_is_not_created(self):
        self.root.mkdir(mode=0o700)
        with patch.object(Path,'mkdir',side_effect=OSError(errno.EROFS,'read-only')) as mkdir:
            with self.assertRaises(helper.SessionNotPrepared):self.reader().path(self.ctx)
        mkdir.assert_not_called();self.assertEqual(list(self.root.iterdir()),[])

    def test_prepared_session_lookup_preserves_all_existing_state(self):
        reader=self.reader();path,_,_=reader.prepare(self.ctx)
        before={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in path.iterdir()}
        with patch.object(Path,'mkdir',side_effect=OSError(errno.EROFS,'read-only')) as mkdir, \
             patch.object(helper,'save',side_effect=AssertionError('read-only lookup')), \
             patch.object(helper,'replace',side_effect=AssertionError('read-only lookup')):
            self.assertEqual(self.reader().path(self.ctx),path)
        mkdir.assert_not_called()
        self.assertEqual(before,{p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in path.iterdir()})

    def test_explicit_preparation_still_creates_private_state(self):
        reader=self.reader();path,credential,request=reader.prepare(self.ctx)
        self.assertEqual(reader.path(self.ctx),path)
        self.assertEqual(self.root.stat().st_mode & 0o777,0o700)
        self.assertEqual(path.stat().st_mode & 0o777,0o700)
        self.assertEqual(credential.stat().st_mode & 0o777,0o600)
        self.assertEqual(request['native_id'],self.ctx['native_id'])

    def test_lookup_keeps_private_path_checks(self):
        reader=self.reader();path,_,_=reader.prepare(self.ctx)
        path.chmod(0o755)
        with self.assertRaises(BridgeError):reader.path(self.ctx)
        path.chmod(0o700)
        other=dict(self.ctx,native_id='20000000-0000-4000-8000-000000000002')
        target=self.root/('codex-auto_'+helper.local_key('mikkel@pop-os',other))
        target.symlink_to(path,target_is_directory=True)
        with self.assertRaises(BridgeError):reader.path(other)

    def test_cli_reports_missing_preparation_without_creating_it(self):
        account=self.base/'trusted-account.json'
        account.write_text(json.dumps({'schema_version':1,'peer':'mikkel@pop-os'}));account.chmod(0o600)
        args=['helper','tool','--client','codex','--account-file',str(account),
              '--native-session',self.ctx['native_id'],'--tool','list_contacts']
        stderr=io.StringIO()
        stdin=SimpleNamespace(buffer=io.BytesIO(b'{}'))
        with patch.object(helper.sys,'argv',args),patch.object(helper.sys,'stdin',stdin), \
             patch.object(helper.os,'environ',{}),contextlib.redirect_stderr(stderr), \
             patch.object(helper.Helper,'call') as network:
            with self.assertRaises(SystemExit) as error:helper.main()
        self.assertEqual(error.exception.code,2);network.assert_not_called()
        self.assertIn('trusted startup hook must prepare it',stderr.getvalue())
        self.assertFalse(self.root.exists())
