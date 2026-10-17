#!/usr/bin/env python3
"""Optional installed-OpenCode transport smoke. No provider call or real mailbox.

Run: python tests/opencode_native_smoke.py /absolute/path/to/opencode
Uses native session APIs/plugin loading in temporary XDG roots. A test adapter
adds noReply to native promptAsync admission; this proves native persistence,
hook context and receiver confirmation, NOT inference/worker acknowledgment.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main():
    binary=sys.argv[1]
    source=(Path(__file__).resolve().parents[1]/'integrations/opencode/babel-wake.mjs').as_uri()
    with tempfile.TemporaryDirectory(prefix='babel-opencode-smoke-') as temporary:
        root=Path(temporary)
        for name in ('config/opencode/plugins','data','cache','state','workspace'):(root/name).mkdir(parents=True)
        log=root/'events.jsonl'
        wrapper='''import Babel from SOURCE;
import {appendFile} from 'node:fs/promises';
export default async (input) => {
  const original=input.client.session.promptAsync.bind(input.client.session);
  input.client.session.promptAsync=(request)=>original({...request,body:{...request.body,noReply:true}});
  let delivered=false;
  return Babel(input,{bridge:async(action,data)=>{
    await appendFile(LOG,JSON.stringify({action,data})+'\\n');
    if(action==='confirm')delivered=true;
    if(action==='poll')return {notifications:delivered?[]:[{message_id:'synthetic-native-contract',native_message_id:'msg_babelnativecontract123456789',text:'Babel mailbox notification for synthetic native contract.',reconcile:false}]};
    return {};
  }});
};'''.replace('SOURCE',json.dumps(source)).replace('LOG',json.dumps(str(log)))
        (root/'config/opencode/plugins/babel-wake.js').write_text(wrapper)
        (root/'config/opencode/opencode.json').write_text('{"$schema":"https://opencode.ai/config.json"}')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        password=secrets.token_hex(24)
        env={**os.environ,'XDG_CONFIG_HOME':str(root/'config'),'XDG_DATA_HOME':str(root/'data'),
             'XDG_CACHE_HOME':str(root/'cache'),'XDG_STATE_HOME':str(root/'state'),
             'OPENCODE_DISABLE_PROJECT_CONFIG':'true','OPENCODE_DISABLE_DEFAULT_PLUGINS':'true',
             'OPENCODE_SERVER_PASSWORD':password,'OPENCODE_SERVER_USERNAME':'opencode'}
        # Avoid inherited project/config injections, while keeping the user's HOME unchanged.
        for name in ('OPENCODE_CONFIG','OPENCODE_CONFIG_DIR','OPENCODE_CONFIG_CONTENT'):env.pop(name,None)
        headers={'Content-Type':'application/json','x-opencode-directory':str(root/'workspace'),
                 'Authorization':'Basic '+base64.b64encode(('opencode:'+password).encode()).decode()}
        def api(path,data=None):
            request=Request(f'http://127.0.0.1:{port}'+path,headers=headers,
                            data=None if data is None else json.dumps(data).encode())
            with urlopen(request,timeout=10) as response:return json.load(response)
        with (root/'server.log').open('w') as server_log:
            process=subprocess.Popen([binary,'serve','--hostname','127.0.0.1','--port',str(port)],
                                     cwd=root/'workspace',env=env,stdout=server_log,stderr=server_log)
            try:
                deadline=time.monotonic()+60
                while True:
                    try:api('/global/health');break
                    except (HTTPError,URLError,TimeoutError,socket.timeout):
                        if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Isolated native server unavailable')
                        time.sleep(.2)
                session=api('/session',{'title':'Babel synthetic native plugin contract'})
                sid=session['id']
                message=api('/session/'+sid+'/message',{'messageID':'msg_nativecontract123456789AB','noReply':True,
                    'parts':[{'type':'text','text':'Verify this isolated native plugin contract.'}]})
                assert message['info']['sessionID']==sid
                while time.monotonic()<deadline:
                    events=[json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
                    if any(item['action']=='confirm' for item in events):break
                    time.sleep(.2)
                else:raise RuntimeError('Native notification was not persisted and confirmed')
                assert any(e['action']=='event' and e['data'].get('hook_event_name')=='session.created' and e['data']['session_id']==sid for e in events)
                assert any(e['action']=='event' and e['data'].get('message_id')=='msg_nativecontract123456789AB' for e in events)
                assert not any(e['action']=='event' and str(e['data'].get('message_id','')).startswith('msg_babel') for e in events)
                native=api('/session/'+sid+'/message/msg_babelnativecontract123456789')
                assert native['info']['role']=='user' and native['info']['sessionID']==sid
                print('PASS: native plugin autoload, exact session lifecycle, native notification persistence and confirmation; no provider call or worker ACK.')
            finally:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)

if __name__=='__main__':main()
