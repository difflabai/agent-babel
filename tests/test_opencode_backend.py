"""Optional private deployment eligibility contract; public CI skips cleanly.

Set BABEL_PRIVATE_BACKEND_ROOT to an explicitly selected backend source directory
when validating the deployment patch. No real accounts, tokens or remote APIs.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import time
import unittest

from babel.auth import Policy
from babel.core import BridgeError, Store


def backend():
    selected=os.environ.get('BABEL_PRIVATE_BACKEND_ROOT')
    if selected:
        path=Path(selected)/'babel/session_leases.py'
        spec=importlib.util.spec_from_file_location('babel.session_leases',path)
    else:spec=importlib.util.find_spec('babel.session_leases')
    if spec is None:return None
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


private_backend=backend()


@unittest.skipIf(private_backend is None,'Private trusted-session backend is not included in this repository')
class OpenCodeBackendTests(unittest.TestCase):
    def setUp(self):
        self.store=Store(':memory:');self.addCleanup(self.store.close)
        self.now=time.time()
        ember='bits255.dots.ada_20261002'
        self.ember=ember
        self.policy=Policy({'schema_version':3,'owners':{'bits255':{'enabled':True}},
            'participants':{ember:{'owner':'bits255','client':'dots','session':'ada_20261002','state':'active',
                'accepted':True,'activated_at':int(self.now)-10,'expires':None,
                'sha256':hashlib.sha256(b'synthetic-only-ember-credential').hexdigest()}},'conversations':{}})

    def leases(self,clients,enabled=True):
        return private_backend.SessionLeases(self.store,{'schema_version':1,
            'accounts':{'mikkel@pop-os':{'enabled':enabled,'clients':clients}},'max_active':8,'max_records':16},clock=lambda:self.now)

    def enroll(self,leases,sid='ses_syntheticnative12345678',**extra):
        return leases.bootstrap(self.policy,peer='mikkel@pop-os',client='opencode',native_id=sid,
            sha256=hashlib.sha256(('synthetic-only-private-'+sid).encode()).hexdigest(),event_id='bootstrap:'+sid,**extra)

    def test_patched_backend_creates_separate_outbound_only_profiles(self):
        leases=self.leases(['codex','opencode'])
        first=self.enroll(leases);second=self.enroll(leases,'ses_syntheticnative12345679')
        self.assertNotEqual(first['participant'],second['participant'])
        self.assertNotEqual(first['conversation'],second['conversation'])
        projected=leases.project(self.policy)
        for record in (first,second):
            pid,cid=record['participant'],record['conversation']
            self.assertEqual(leases.row(pid)['profile'],'ember_outbound')
            self.assertEqual(projected.agents[pid][1],frozenset((self.ember,)))
            self.assertEqual(projected.conversations[cid]['routes'],[{'sender':pid,'recipient':self.ember}])
        self.assertNotIn((first['conversation'],first['participant'],second['participant']),projected.routes)
        self.assertNotIn((first['conversation'],self.ember,first['participant']),projected.routes)

    def test_static_capability_does_not_override_account_client_or_enabled_gates(self):
        with self.assertRaises(BridgeError):self.enroll(self.leases(['codex']))
        with self.assertRaises(BridgeError):self.enroll(self.leases(['opencode'],enabled=False))
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM trusted_sessions').fetchone()[0],0)
