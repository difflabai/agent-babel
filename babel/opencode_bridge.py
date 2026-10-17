"""OpenCode's native plugin owns polling; this helper never launches a receiver.

Only runtime-observed root sessions are passed in. Polls neither bootstrap nor
renew identities. An opt-in account transport can drain existing native evidence.
A durable native submission intent is never blindly retried.
The plugin confirms the exact native message before committing acceptance.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time
from urllib.error import HTTPError

from account_session_helper import Helper, TOOLS, bind_reviewed, private
from babel.account_bootstrap import context, local_key
from babel.account_wake import (Delivery, Mailbox, Quarantined, fingerprint,
                                locked, notice, read_json, write_json)
from babel.core import BridgeError, identifier
from babel.lifecycle_dispatcher import Dispatcher
from babel.native_lifecycle import event_key


def bootstrap_state(path, sid):
    """Only fresh unaccepted evidence for this existing automatic identity."""
    if any((path/name).exists() or (path/name).is_symlink() for name in
           ('resume-token','resume-event.json','rotation-journal.json','token.pending')):
        return None
    manifest=read_json(path/'trusted-enrollment.json',4096)
    evidence=path/'lifecycle-events'/(event_key('bootstrap:'+sid)[7:]+'.json')
    if not evidence.exists() and not evidence.is_symlink():return None
    request=read_json(evidence,4096)
    if not isinstance(manifest,dict) or not isinstance(request,dict):
        raise BridgeError('Invalid native enrollment metadata')
    for value in (manifest,request):
        sha=value.get('sha256')
        if (not isinstance(sha,str) or len(sha)!=64 or sha=='0'*64
                or any(char not in '0123456789abcdef' for char in sha)):
            raise BridgeError('Invalid native credential digest metadata')
        if (value.get('client')!='opencode' or value.get('native_id')!=sid or
                value.get('kind')!='bootstrap' or value.get('event_id')!='bootstrap:'+sid):
            return None
    if manifest.get('sha256')!=request.get('sha256'):return None
    observed=request.get('observed_at')
    if (type(observed) not in (int,float) or not math.isfinite(observed)
            or not 0<=time.time()-observed<86400):return None
    receipt=evidence.with_suffix('.receipt')
    if receipt.exists() or receipt.is_symlink():
        private(receipt)
        from babel.account_enrollment import digest
        if receipt.stat().st_size>128 or receipt.read_text()!=digest(request)+'\n':
            raise BridgeError('Native enrollment acceptance evidence changed')
        return 'accepted' # Auth failure here is distinct from pending enrollment.
    return 'pending'


def pending_bootstrap(path, sid):
    return bootstrap_state(path,sid)=='pending'


def contact_read(call, state, *, pending_call=None, clock=time.monotonic, sleep=time.sleep):
    """Bounded HTTP401 readiness for new identities, never enrollment/mutations."""
    current=state()
    if current!='pending':return call() # Ordinary20sec helper behavior; no new retry.
    read=pending_call or call
    deadline=clock()+12
    delay=1
    last_error=None
    while True:
        remaining=deadline-clock()
        if remaining<=0:
            if current=='pending' and last_error is not None:
                return {'verified':False,'status':'awaiting_operator_enrollment','retry_after':20}
            raise last_error or TimeoutError('Native authentication readiness deadline')
        before=current
        try:return read(timeout=min(20,remaining))
        except HTTPError as error:
            if error.code!=401:raise
            last_error=error
            current=state() # Malformed/local/rotation evidence never becomes pending.
            if current=='accepted':
                if before=='pending':
                    continue # One immediate authoritative read after acceptance raced this401.
                raise # Persistent accepted401 is not pending enrollment.
            if current!='pending':raise
            remaining=deadline-clock()
            if remaining<=0:
                return {'verified':False,'status':'awaiting_operator_enrollment','retry_after':20}
            sleep(min(delay,remaining))
            delay=min(delay+1,4)
            current=state()
            if current not in ('pending','accepted'):raise last_error


class NativeAdmission(RuntimeError):
    """Stop before Delivery can commit its native submission result."""
    def __init__(self, text):
        self.text = text


def native_message_id(box, mid):
    return 'msg_babel' + hashlib.sha256((box.participant + ':' + box.sid + ':' + mid).encode()).hexdigest()[:32]


def pending(box, state):
    if (set(state) != {'schema_version','native_id','participant','submissions'}
            or state['schema_version'] != 1 or state['native_id'] != box.sid
            or state['participant'] != box.participant or not isinstance(state['submissions'],dict)
            or len(state['submissions']) > 8192):
        raise Quarantined('Retain mismatched native delivery ledger')
    results = []
    for mid, item in state['submissions'].items():
        identifier(mid)
        claim = 'wake_' + hashlib.sha256((box.participant + ':' + box.sid + ':' + mid).encode()).hexdigest()
        if (not isinstance(item,dict) or set(item) != {'state','claim_id','fingerprint'}
                or item['claim_id'] != claim or item['state'] not in ('reserving','submitting','accepted')
                or not isinstance(item['fingerprint'],str) or len(item['fingerprint']) != 64
                or any(c not in '0123456789abcdef' for c in item['fingerprint'])):
            raise Quarantined('Retain uncertain delivery ledger')
        if item['state'] != 'accepted':
            if item['state'] != 'submitting':
                raise Quarantined('Claim outcome needs reconciliation')
            results.append({'message_id':mid,'native_message_id':native_message_id(box,mid),
                            'text':notice(box,mid,claim),'reconcile':True})
    if len(results) > 1:
        raise Quarantined('Multiple uncertain native admissions')
    return results


class Bridge:
    def __init__(self, account_file):
        self.account_file = Path(account_file)
        config=read_json(self.account_file,4096)
        if set(config)!={'schema_version','peer'} or config['schema_version']!=1:
            raise BridgeError('Invalid account configuration')
        self.root=self.account_file.parent
        self.helper=Helper(self.root/'automatic-instances',config['peer'])

    def event(self, data):
        sid = data['session_id']
        # Existing sessions first encountered through an actual prompt also get
        # their own identity. The native plugin has read this exact SessionInfo;
        # this observation does not claim resume or meaningful completed work.
        ctx = context('opencode',hook={'hook_event_name':'session.observed','session_id':sid})
        if data.get('parent_id'):
            return {'status':'ignored'}
        dispatcher = Dispatcher(self.helper)
        path = self.helper.root / ('opencode-auto_' + local_key(self.helper.peer,ctx))
        if data.get('hook_event_name') == 'chat.message' and not (path/'token').exists():
            dispatcher.dispatch('opencode', {'hook_event_name':'session.observed','session_id':sid})
        result=dispatcher.dispatch('opencode',data)
        if result.get('status') in ('queued','tracked'):
            from babel.account_enrollment import ensure_enrollment
            ensure_enrollment(self.account_file, fresh=result.get('status') == 'queued')
        return result

    def tool(self, sid, operation, arguments):
        if not isinstance(operation,str) or operation not in TOOLS or not isinstance(arguments,dict):
            raise BridgeError('Unsupported native Babel tool')
        ctx=context('opencode',hook={'hook_event_name':'session.observed','session_id':sid})
        # Read only an existing exact native mailbox. A native tool never
        # bootstraps another context or adopts an identity by name.
        bind_reviewed(self.helper,self.root,ctx)
        path=(self.helper.legacy[1] if self.helper.legacy else
              self.helper.root/('opencode-auto_'+local_key(self.helper.peer,ctx)))
        private(path,True)
        if not (path/'token').exists():raise BridgeError('Native mailbox is not prepared')
        from babel.account_enrollment import ensure_enrollment
        ensure_enrollment(self.account_file)
        call=lambda **options:self.helper.call(path,operation,arguments,**options)
        if operation=='list_contacts' and not self.helper.legacy:
            manifest=read_json(path/'trusted-enrollment.json',4096)
            if not isinstance(manifest,dict) or not isinstance(manifest.get('sha256'),str):
                raise BridgeError('Invalid native enrollment metadata')
            # Explicit committed credential avoids recursive resume verification
            # or rotation inside a bounded new-bootstrap authentication read.
            pending_call=lambda **options:self.helper.call(path,operation,arguments,
                credential=path/'token',expected_digest=manifest['sha256'],**options)
            result=contact_read(call,lambda:bootstrap_state(path,sid),pending_call=pending_call)
        else:result=call()
        from babel.reporting import with_reporting_policy
        return with_reporting_policy(path,result)

    def poll(self, sid):
        from babel.account_enrollment import ensure_enrollment
        ensure_enrollment(self.account_file)
        box = Mailbox(self.root,self.helper,sid,client='opencode')
        with locked(box.path/'account-wake.lock'):
            state_path = box.path/'account-wake-state.json'
            if state_path.exists():
                old = pending(box,read_json(state_path))
                if old:
                    return {'notifications':old}
            class Native:
                def metadata(self, target):
                    if target != sid: raise BridgeError('Native session mismatch')
                    return {'cwd':''}
                def queue(self, target, cwd, text, expires):
                    if target != sid: raise BridgeError('Native session mismatch')
                    raise NativeAdmission(text)
            delivery = Delivery(box,Native())
            try:
                delivery.step()
            except NativeAdmission:
                result = pending(box,delivery.state)
                result[0]['reconcile'] = False
                return {'notifications':result}
            return {'notifications':[]}

    def confirm(self, sid, data):
        box = Mailbox(self.root,self.helper,sid,client='opencode')
        with locked(box.path/'account-wake.lock'):
            path = box.path/'account-wake-state.json'
            state = read_json(path)
            requests = pending(box,state)
            if len(requests) != 1:
                raise Quarantined('No pending native admission')
            request = requests[0]
            if (data.get('native_message_id') != request['native_message_id'] or data.get('text') != request['text']
                    or data.get('message_id') != request['message_id']):
                raise Quarantined('Native admission proof mismatch')
            mid = request['message_id']
            # ACK remains exclusively the awakened worker's responsibility.
            # Message fingerprint must still match the exact claim we reserved.
            latest = box.call('message_status',{'message_id':mid})['message']
            if fingerprint(latest) != state['submissions'][mid]['fingerprint']:
                raise Quarantined('Native admission message changed')
            state['submissions'][mid]['state'] = 'accepted'
            write_json(path,state)
            return {'status':'accepted'}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account-file',required=True)
    parser.add_argument('--action',choices=('event','poll','confirm','tool'),required=True)
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw)>65536: raise BridgeError('Plugin input too large')
        data=json.loads(raw)
        bridge=Bridge(args.account_file)
        if args.action=='event': result=bridge.event(data)
        elif args.action=='poll': result=bridge.poll(data['session_id'])
        elif args.action=='tool': result=bridge.tool(data['session_id'],data['operation'],data['arguments'])
        else: result=bridge.confirm(data['session_id'],data)
        print(json.dumps(result))
    except (BridgeError,Quarantined,OSError,ValueError,KeyError,RuntimeError):
        # Provider payloads, private endpoint errors and credentials stay local.
        parser.exit(2,'Babel OpenCode integration unavailable; pending evidence retained.\n')
