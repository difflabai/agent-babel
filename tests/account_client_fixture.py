"""Synthetic account-client fixtures, independent of unpublished server features."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch
from account_lifecycle_hook import Dispatcher
from account_session_helper import Helper

SID='20000000-0000-4000-8000-000000000001'
TURN='10000000-0000-4000-8000-000000000001'
TURN2='10000000-0000-4000-8000-000000000002'

def cli_command(script, account):
    # CI runs under an arbitrary UNIX name; the fixture asserts the approved
    # peer only inside this synthetic child, never in installed application code.
    code="""import runpy,sys,pwd
from pathlib import Path
from types import SimpleNamespace
pwd.getpwuid=lambda uid:SimpleNamespace(pw_name='mikkel')
script=sys.argv[1];sys.path.insert(0,str(Path(script).resolve().parent))
sys.argv=[script,'--client','claude','--account-file',sys.argv[2]]
runpy.run_path(script,run_name='__main__')
"""
    return [sys.executable,'-c',code,str(script),str(account)]

class DispatcherTests:
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
