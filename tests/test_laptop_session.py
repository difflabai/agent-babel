import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from babel.core import BridgeError
from laptop_session_helper import submit


class LaptopOperatorTests(unittest.TestCase):
    def test_fixed_peer_digest_only_request_over_verified_ssh(self):
        request={'schema_version':2,'client':'codex','native_id':'10000000-0000-4000-8000-000000000001',
                 'sha256':'1'*64,'event_id':'bootstrap:fixture-native-01','kind':'bootstrap'}
        calls=[]
        def runner(argv, **kwargs):
            calls.append((argv,kwargs))
            return SimpleNamespace(returncode=0,stdout='{"participant":"fixture-native-mailbox"}')
        with patch('pwd.getpwuid',return_value=SimpleNamespace(pw_name='ntc')),patch('socket.gethostname',return_value='laptop'):
            self.assertEqual(submit(request,runner)['participant'],'fixture-native-mailbox')
        argv,kwargs=calls[0]
        self.assertIn('StrictHostKeyChecking=yes',argv)
        self.assertEqual(argv[-1],'ntc@laptop')
        self.assertEqual(json.loads(kwargs['input']),request)
        self.assertNotIn('token',kwargs['input'])
    def test_another_account_or_host_cannot_submit_as_laptop(self):
        for user,host in (('root','laptop'),('ntc','other-host')):
            with patch('pwd.getpwuid',return_value=SimpleNamespace(pw_name=user)),patch('socket.gethostname',return_value=host):
                with self.assertRaises(BridgeError):submit({'schema_version':2},lambda *_: self.fail('SSH must not run'))
    def test_legacy_or_worker_supplied_peer_cannot_select_admission(self):
        with patch('pwd.getpwuid',return_value=SimpleNamespace(pw_name='ntc')),patch('socket.gethostname',return_value='laptop'):
            for request in ({'schema_version':1},{'schema_version':2,'peer':'work@pop-os'}):
                with self.assertRaises(BridgeError):submit(request,lambda *_: self.fail('SSH must not run'))
