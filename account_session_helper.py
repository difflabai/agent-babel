#!/usr/bin/env python3
"""Opt-in Pop account helper. Private token, no per-session name/enrollment UI.

The pinned operator collector submits trusted-enrollment.json (digest only).
This program is not installed/enabled by this patch. Existing babel-instance
mailboxes and files are never modified. Same-UID processes are trusted together.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import sys
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPRedirectHandler
from babel.account_bootstrap import context, local_key, PEERS, NATIVE
from babel.core import BridgeError

BASE='https://babel.255bits.com/mcp/v1'
TOOLS=frozenset(('list_contacts','stage_message','receive_messages','claim_message','acknowledge_message','message_status','bridge_history','stage_report','read_report'))


def private(path, directory=False):
    for item in (path,*path.parents):
        if item.is_symlink():raise BridgeError('Account helper refuses symlinked paths')
    info=path.stat()
    if info.st_uid!=os.getuid() or info.st_mode & 0o077 or (directory and not stat.S_ISDIR(info.st_mode)) or (not directory and not stat.S_ISREG(info.st_mode)):
        raise BridgeError('Account helper needs owned private files/directories')


def save(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:
        f.write(value);f.flush();os.fsync(f.fileno())


def replace(path,value):
    tmp=path.with_name(path.name+'.pending')
    save(tmp,value)
    os.replace(tmp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def recover_rotation(path):
    journal=path/'rotation-journal.json'
    if not journal.exists() and not journal.is_symlink():return
    private(journal);record=json.loads(journal.read_text())
    if set(record)!={'event_id','sha256'}:raise BridgeError('Invalid rotation journal; preserve for reconciliation')
    candidate=path/'resume-token'
    current=candidate if candidate.exists() else path/'token';private(current)
    if hashlib.sha256(current.read_text().strip().encode()).hexdigest()!=record['sha256']:raise BridgeError('Rotation journal does not match retained credential')
    enrollment=path/'enrollment.json'
    if enrollment.exists() or enrollment.is_symlink():
        private(enrollment);manifest=json.loads(enrollment.read_text());manifest['sha256']=record['sha256']
        replace(enrollment,json.dumps(manifest)+'\n')
    if current==candidate:os.replace(candidate,path/'token')
    replace(path/'last-resume.json',json.dumps(record)+'\n')
    event=path/'resume-event.json'
    if event.exists():private(event);event.unlink()
    journal.unlink()
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def bind_reviewed(helper, config_dir, ctx):
    """Exact operator-reviewed native-to-legacy mapping; never scan/adopt by name."""
    mapping=Path(config_dir)/'native-bindings.json'
    if not mapping.exists() and not mapping.is_symlink():return
    private(mapping)
    if mapping.stat().st_size>16384:raise BridgeError('Native binding map too large')
    data=json.loads(mapping.read_text())
    if set(data)!={'schema_version','bindings'} or data['schema_version']!=1 or not isinstance(data['bindings'],dict) or len(data['bindings'])>64:
        raise BridgeError('Invalid reviewed native binding map')
    name=data['bindings'].get(ctx['client']+':'+ctx['native_id'])
    if name is None:return
    import re
    if not isinstance(name,str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,23}',name):
        raise BridgeError('Invalid reviewed legacy instance name')
    helper.use_legacy(ctx,Path(config_dir)/'instances'/(ctx['client']+'-'+name))


class Helper:
    def __init__(self, root, peer, *, token_factory=None):
        if peer not in PEERS or pwd.getpwuid(os.getuid()).pw_name!=peer.split('@')[0]:
            raise BridgeError('Automatic worker account is not approved',403)
        self.root,self.peer=Path(root),peer
        self.token_factory=token_factory or (lambda:secrets.token_hex(32))
        self.legacy=None
        if not self.root.exists():self.root.mkdir(mode=0o700,parents=True)
        private(self.root,True)

    def use_legacy(self,ctx,path):
        path=Path(path);private(path,True)
        recover_rotation(path)
        enrollment=path/'enrollment.json';private(enrollment)
        request=json.loads(enrollment.read_text())
        if request.get('client')!=ctx['client']:raise BridgeError('Legacy client mismatch')
        token=path/'token';private(token)
        if request.get('sha256')!=hashlib.sha256(token.read_text().strip().encode()).hexdigest():raise BridgeError('Legacy instance digest mismatch')
        binding=path/'account-native-binding.json'
        expected={'peer':self.peer,'client':ctx['client'],'native_id':ctx['native_id'],'participant':request.get('participant')}
        if binding.exists() or binding.is_symlink():
            private(binding)
            if json.loads(binding.read_text())!=expected:raise BridgeError('Legacy instance already bound to another context')
        else:save(binding,json.dumps(expected)+'\n')
        self.legacy=(ctx,path)

    def path(self,ctx):
        if self.legacy:
            if self.legacy[0]!=ctx:raise BridgeError('Legacy native context mismatch')
            private(self.legacy[1],True);return self.legacy[1]
        path=self.root/(ctx['client']+'-auto_'+local_key(self.peer,ctx))
        if not path.exists():path.mkdir(mode=0o700)
        private(path,True)
        return path

    def prepare(self,ctx,resume_event=None):
        import fcntl
        path=self.path(ctx)
        fd=os.open(path/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            recover_rotation(path)
            tokenfile=path/'token'
            if not tokenfile.exists():
                if any(p.name!='lock' for p in path.iterdir()):raise BridgeError('Incomplete instance; preserve and inspect before retry')
                save(tokenfile,self.token_factory()+'\n')
            private(tokenfile)
            token=tokenfile.read_text().strip()
            credential=tokenfile
            if resume_event:
                if not isinstance(resume_event,str) or not NATIVE.fullmatch(resume_event):raise BridgeError('Fresh account-local resume event required')
                candidate=path/'resume-token'
                manifest=path/'resume-event.json'
                last=path/'last-resume.json'
                previous=json.loads(last.read_text()) if last.exists() else None
                if previous and previous.get('event_id')==resume_event:
                    private(last)
                    if previous.get('sha256')!=hashlib.sha256(token.encode()).hexdigest():raise BridgeError('Previously committed resume token changed')
                    candidate=tokenfile
                elif candidate.exists():
                    private(candidate);private(manifest)
                    if json.loads(manifest.read_text())!={'event_id':resume_event}:raise BridgeError('A different resume is pending; reconcile it first')
                else:
                    save(candidate,self.token_factory()+'\n');save(manifest,json.dumps({'event_id':resume_event}))
                token=candidate.read_text().strip();credential=candidate
            if not isinstance(token,str) or not 32<=len(token)<=256 or not all(c.isalnum() or c in '_-' for c in token):raise BridgeError('Invalid private session credential')
            request={'schema_version':2,**ctx,'sha256':hashlib.sha256(token.encode()).hexdigest()}
            if resume_event:request.update(kind='resume',event_id=resume_event)
            if self.legacy:
                request['existing_participant']=json.loads((path/'enrollment.json').read_text())['participant']
            name=path/'trusted-enrollment.json'
            if name.exists() or name.is_symlink():private(name)
            replace(name,json.dumps(request,sort_keys=True)+'\n')
            if self.legacy:
                spool=self.root/(ctx['client']+'-auto_'+local_key(self.peer,ctx))
                if not spool.exists():spool.mkdir(mode=0o700)
                private(spool,True)
                target=spool/'trusted-enrollment.json'
                if target.exists() or target.is_symlink():private(target)
                replace(target,json.dumps(request,sort_keys=True)+'\n')
            return path,credential,request
        finally:os.close(fd)

    def call(self,path,tool,args,credential=None,expected_digest=None,timeout=20):
        if tool not in TOOLS:raise BridgeError('Unsupported helper tool')
        if type(timeout) not in (int,float) or not 0<timeout<=20:raise BridgeError('Invalid helper request timeout')
        if expected_digest is not None and credential is None:
            raise BridgeError('Pinned tool calls require an explicit existing credential')
        if tool in ('stage_report','read_report'):
            from babel.reporting import report_tool,local_store
            return report_tool(local_store(path),tool,args,lambda name,data:self.call(path,name,data,credential,expected_digest))
        if credential is None and (path/'resume-token').exists():
            # Authenticated verification commits the retained candidate in place.
            # No fresh credential is minted by a tool call or a retry.
            self.verify(path,path/'resume-token')
        credential=credential or path/'token';private(credential)
        token=credential.read_text().strip()
        if expected_digest is not None and hashlib.sha256(token.encode()).hexdigest()!=expected_digest:
            raise BridgeError('Pinned session credential changed',403)
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        data={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':tool,'arguments':args}}
        req=Request(BASE,data=json.dumps(data).encode(),headers={'Authorization':'Bearer '+token,
            'Content-Type':'application/json','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-11-25'})
        with build_opener(NoRedirect()).open(req,timeout=timeout) as response:payload=json.load(response)
        if 'error' in payload or payload['result'].get('isError'):raise BridgeError('Authenticated Babel helper call failed')
        return json.loads(payload['result']['content'][0]['text'])

    def verify(self,path,credential):
        import fcntl
        fd=os.open(path/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            if not credential.exists() and (path/'last-resume.json').exists():credential=path/'token'
            contacts=self.call(path,'list_contacts',{},credential)['contacts']
            if self.legacy:
                if not contacts or not any(c['recipient'] in ('bits255.dots.ada_20261002','bits255.grokbot.grok_20261002') for c in contacts):raise BridgeError('Legacy reporting grants unavailable',403)
            elif len(contacts)!=1 or contacts[0]['recipient']!='bits255.dots.ada_20261002':raise BridgeError('Default reporting profile mismatch',403)
            if credential.name=='resume-token':
                # Journal only after authenticated confirmation. A crash between
                # legacy metadata and token replacement is locally recoverable.
                event=json.loads((path/'resume-event.json').read_text())
                event['sha256']=hashlib.sha256(credential.read_text().strip().encode()).hexdigest()
                replace(path/'rotation-journal.json',json.dumps(event)+'\n')
                recover_rotation(path)
            return {'verified':True,'contacts':contacts}
        finally:os.close(fd)


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('bootstrap','tool'))
    p.add_argument('--client',choices=('codex','claude','cursor','opencode','grokbot'),required=True)
    p.add_argument('--account-file',required=True,help='Owned private one-time account config, not a secret')
    p.add_argument('--hook-context',action='store_true',help='Read actual Claude/Cursor SessionStart JSON on stdin')
    p.add_argument('--resume-event',help='Fresh real runtime/user resume event; never from a poll/retry')
    p.add_argument('--tool',choices=sorted(TOOLS))
    p.add_argument('--legacy-instance',help='Reviewed same-session legacy instance directory; preserves its credential location and grants')
    p.add_argument('--native-session',help='Actual Claude/Cursor context captured by its account-local startup hook')
    a=p.parse_args()
    try:
        config=Path(a.account_file);private(config)
        if config.stat().st_size>4096:raise BridgeError('Account configuration too large')
        cfg=json.loads(config.read_text())
        if set(cfg)!= {'schema_version','peer'} or cfg['schema_version']!=1:raise BridgeError('Invalid account config')
        if a.action=='tool' and (a.hook_context or a.resume_event):raise BridgeError('Tool reads cannot create lifecycle activity')
        raw=sys.stdin.buffer.read(65537) if a.hook_context or a.action=='tool' else b'{}'
        if len(raw)>65536:raise BridgeError('Helper input too large')
        data=json.loads(raw)
        hook=data if a.hook_context else None
        if a.native_session:
            if a.hook_context:raise BridgeError('Conflicting native contexts')
            hook={'hook_event_name':'SessionStart' if a.client in ('claude','codex','grokbot') else 'session.observed' if a.client=='opencode' else 'sessionStart','session_id':a.native_session}
        if a.client in ('opencode','grokbot') and a.legacy_instance and not hook:
            if not a.legacy_instance or hook or a.native_session:raise BridgeError('This automatic native adapter is unavailable')
            legacy=Path(a.legacy_instance);private(legacy,True);file=legacy/'enrollment.json';private(file)
            old=json.loads(file.read_text())
            if old.get('client')!=a.client or not isinstance(old.get('participant'),str):raise BridgeError('Legacy context mismatch')
            native='legacy:'+hashlib.sha256(old['participant'].encode()).hexdigest()[:32]
            ctx={'client':a.client,'native_id':native,'kind':'bootstrap','event_id':'bootstrap:'+native}
        else:ctx=context(a.client,hook=hook)
        helper=Helper(config.parent/'automatic-instances',cfg['peer'])
        if a.legacy_instance:helper.use_legacy(ctx,a.legacy_instance)
        else:bind_reviewed(helper,config.parent,ctx)
        if a.action=='bootstrap':
            path,credential,request=helper.prepare(ctx,a.resume_event)
            try:result=helper.verify(path,credential)
            except HTTPError as exc:
                if exc.code not in (401,403):raise
                result={'verified':False,'status':'awaiting_operator_enrollment','request_file':str(path/'trusted-enrollment.json')}
        else:
            if not a.tool:raise BridgeError('Select a helper tool')
            path=helper.path(ctx)
            if not (path/'token').exists():raise BridgeError('This native session is not bootstrapped')
            result=helper.call(path,a.tool,data)
            from babel.reporting import with_reporting_policy
            result=with_reporting_policy(path,result)
        print(json.dumps(result))
    except (BridgeError,OSError,ValueError,KeyError):
        # Never dump exception URLs, tokens, config, headers or provider payloads.
        p.exit(2,'Babel account helper failed; preserve its existing instance and private enrollment request.\n')

if __name__=='__main__':main()
