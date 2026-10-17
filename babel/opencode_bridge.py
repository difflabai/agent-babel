"""OpenCode's native plugin owns polling; this helper never launches a receiver.

Only runtime-observed root sessions are passed in. Polls neither bootstrap nor
renew identities. A durable native submission intent is never blindly retried.
The plugin confirms the exact native message before committing acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from account_session_helper import Helper, TOOLS, bind_reviewed, private
from babel.account_bootstrap import context, local_key
from babel.account_wake import (Delivery, Mailbox, Quarantined, fingerprint,
                                locked, notice, read_json, write_json)
from babel.core import BridgeError, identifier
from babel.lifecycle_dispatcher import Dispatcher


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
        return dispatcher.dispatch('opencode',data)

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
        result=self.helper.call(path,operation,arguments)
        from babel.reporting import with_reporting_policy
        return with_reporting_policy(path,result)

    def poll(self, sid):
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
