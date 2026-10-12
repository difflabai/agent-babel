#!/usr/bin/env python3
"""Draft pinned-SSH collector; no timer/service install and dry-run by default.

Only schema2 digest requests under the two approved account-local roots. It never
reads token files, edits native sessions, or infers activity from a scan. Repeated
lifecycle event IDs are deduplicated by the server, not a volatile collector cache.
"""
import argparse
import json
import subprocess
import hashlib
import os
from pathlib import Path
from account_session_helper import private, replace
from babel.core import BridgeError
from babel.session_leases import PEERS, SessionLeases
from babel.account_bootstrap import local_key

SSH_OPTIONS=['-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','PreferredAuthentications=publickey',
             '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','ConnectTimeout=8']
# This fixed remote program reads ONLY lifecycle JSON metadata, never token or env.
REMOTE=r'''
import json,os,re,stat,hashlib
from pathlib import Path
root=Path.home()/'.config/255bits/agent-babel/automatic-instances'
uid=os.getuid();out=[]
def owned(p,directory=False):
 if any(x.is_symlink() for x in (p,*p.parents)):return False
 try:s=p.stat()
 except OSError:return False
 return s.st_uid==uid and not s.st_mode&0o077 and (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
if root.exists() and owned(root,True):
 for folder in sorted(root.iterdir()):
  if len(out)>=4096:break
  if not re.fullmatch(r'(codex|claude|cursor|opencode|grokbot)-auto_[a-f0-9]{32}',folder.name) or not owned(folder,True):continue
  spool=folder/'lifecycle-events'
  if (spool.exists() or spool.is_symlink()) and not owned(spool,True):continue
  files=sorted(spool.glob('*.json')) if spool.exists() and owned(spool,True) else [folder/'trusted-enrollment.json']
  for file in files:
   if len(out)>=4096:break
   if not owned(file) or file.stat().st_size>4096:continue
   try:request=json.loads(file.read_text())
   except (ValueError,UnicodeError,OSError):continue
   receipt=file.with_suffix('.receipt')
   if receipt.exists() and owned(receipt) and receipt.stat().st_size<128:
    expected=hashlib.sha256(json.dumps(request,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if receipt.read_text().strip()==expected:continue
   out.append({'folder':folder.name,'request':request})
out.sort(key=lambda item:item['request'].get('observed_at',0))
print(json.dumps(out))
'''


def validate(peer,item):
    if peer not in PEERS or not isinstance(item,dict) or set(item)!={'folder','request'}:
        raise BridgeError('Unapproved collector account or invalid request')
    request=item['request']
    if not isinstance(request,dict) or (set(request)-{'existing_participant','observed_at'})!={'schema_version','client','native_id','sha256','event_id','kind'} or type(request['schema_version']) is not int or request['schema_version']!=2:
        raise BridgeError('Invalid automatic lifecycle request')
    SessionLeases._request(**{k:v for k,v in request.items() if k not in ('schema_version','existing_participant','observed_at')})
    if 'observed_at' in request:
        import math
        if type(request['observed_at']) not in (int,float) or not math.isfinite(request['observed_at']) or request['observed_at']<=0:
            raise BridgeError('Invalid native observation metadata')
    if item['folder']!=request['client']+'-auto_'+local_key(peer,request):
        raise BridgeError('Collector folder/native context mismatch')
    return request


def collect(peer,runner=subprocess.run):
    if peer not in PEERS:raise BridgeError('Unapproved collector account')
    result=runner(['ssh',*SSH_OPTIONS,peer,'python3','-c',__import__('shlex').quote(REMOTE)],capture_output=True,text=True,timeout=20)
    if result.returncode:raise BridgeError('Pinned SSH collector unavailable')
    if len(result.stdout.encode())>4194304:raise BridgeError('Collector response too large')
    try:items=json.loads(result.stdout)
    except ValueError:raise BridgeError('Invalid collector response') from None
    if not isinstance(items,list) or len(items)>4096:raise BridgeError('Collector request capacity reached')
    return [validate(peer,item) for item in items]


def submit(peer,request,runner=subprocess.run):
    if peer not in PEERS:raise BridgeError('Unapproved collector account')
    # The restricted private command is a PROPOSED installation path. It accepts
    # verified peer as operator metadata; worker JSON cannot override that peer.
    result=runner(['ssh',*SSH_OPTIONS,'root@159.195.17.119','/usr/local/sbin/agent-babel-trusted-session',peer],
                  input=json.dumps(request),capture_output=True,text=True,timeout=30)
    if result.returncode:raise BridgeError('Private operator lifecycle command failed')
    return json.loads(result.stdout)



def fingerprint(peer,request):
    return hashlib.sha256(json.dumps([peer,request],sort_keys=True,separators=(',',':')).encode()).hexdigest()


def acknowledge_spool(peer,request,runner):
    if 'observed_at' not in request:return
    # Account-owned digest metadata only. Receipt preserves the evidence file;
    # uncertain receipt writes retry without another server activity submission.
    program=r'''
import json,os,stat,hashlib
from pathlib import Path
r=json.load(__import__('sys').stdin)
key=hashlib.sha256(json.dumps([r['peer'],r['request']['client'],r['request']['native_id']],separators=(',',':')).encode()).hexdigest()[:32]
eid='native:'+hashlib.sha256(json.dumps([r['request']['event_id']],separators=(',',':')).encode()).hexdigest()
file=Path.home()/'.config/255bits/agent-babel/automatic-instances'/(r['request']['client']+'-auto_'+key)/'lifecycle-events'/(eid[7:]+'.json')
for p in (file,*file.parents):
 if p.is_symlink():raise RuntimeError('Symlink refused')
s=file.stat()
if s.st_uid!=os.getuid() or s.st_mode&0o077 or not stat.S_ISREG(s.st_mode) or s.st_size>4096:raise RuntimeError('Private metadata required')
if json.loads(file.read_text())!=r['request']:raise RuntimeError('Evidence changed')
value=hashlib.sha256(json.dumps(r['request'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
receipt=file.with_suffix('.receipt')
try:
 fd=os.open(receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:f.write(value+'\n');f.flush();os.fsync(f.fileno())
except FileExistsError:
 if receipt.is_symlink() or receipt.read_text().strip()!=value:raise RuntimeError('Receipt conflict')
fd=os.open(file.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
'''
    result=runner(['ssh',*SSH_OPTIONS,peer,'python3','-c',__import__('shlex').quote(program)],
                  input=json.dumps({'peer':peer,'request':request}),text=True,capture_output=True,timeout=20)
    if result.returncode:raise BridgeError('Lifecycle receipt pending; server dedup retained')


def apply_pending(peer,requests,ledger_file,runner=subprocess.run):
    import fcntl
    path=Path(ledger_file)
    private(path.parent,True)
    lock=path.with_name(path.name+'.lock')
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        completed=set()
        if path.exists() or path.is_symlink():
            private(path)
            if path.stat().st_size>4194304:raise BridgeError('Collector dedup capacity reached')
            values=json.loads(path.read_text())
            if not isinstance(values,list) or len(values)>32768 or any(not isinstance(v,str) or not __import__('re').fullmatch('[a-f0-9]{64}',v) for v in values):raise BridgeError('Invalid collector ledger')
            completed=set(values)
        count=0;handled=0
        for request in requests:
            key=fingerprint(peer,request)
            if key in completed:
                acknowledge_spool(peer,request,runner)
                handled+=int('observed_at' in request)
                if handled>=4:break
                continue
            if len(completed)>=32768:raise BridgeError('Collector dedup capacity reached; preserve records')
            import time
            stale='observed_at' in request and time.time()-request['observed_at']>=86400
            if not stale:submit(peer,request,runner)
            completed.add(key);replace(path,json.dumps(sorted(completed))+'\n')
            acknowledge_spool(peer,request,runner)
            # Old evidence is retained and marked consumed locally without a
            # server call. It must not block later genuine work or revive access.
            count+=int(not stale);handled+=1
            if handled>=4:break
        return count
    finally:os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--peer',choices=sorted(PEERS),action='append',required=True)
    p.add_argument('--apply',action='store_true',help='Explicitly invoke the private operator command; default is metadata counts only')
    p.add_argument('--ledger',help='Existing owned private directory plus collector dedup filename; required for --apply')
    a=p.parse_args()
    if a.apply and not a.ledger:p.error('--apply requires --ledger')
    try:
        for peer in a.peer:
            requests=collect(peer)
            submitted=apply_pending(peer,requests,a.ledger) if a.apply else 0
            print(json.dumps({'peer':peer,'requests':len(requests),'submitted':submitted,'mode':'apply' if a.apply else 'dry-run'}))
    except (BridgeError,subprocess.SubprocessError,ValueError,OSError):
        p.exit(2,'Collector did not complete; preserve pending requests and existing mailboxes.\n')

if __name__=='__main__':main()
