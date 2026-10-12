#!/usr/bin/env python3
"""Own native laptop mailbox over the operator's existing verified SSH route."""
import argparse
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
from urllib.error import HTTPError

from account_session_helper import Helper, TOOLS, private, bind_reviewed
from babel.account_bootstrap import context
from babel.core import BridgeError

PEER = 'ntc@laptop'
OPERATOR = 'root@159.195.17.119'


def submit(request, runner=subprocess.run):
    # Peer is fixed operator metadata from this approved UNIX account, never a
    # field accepted from worker JSON. Only the credential digest leaves here.
    if pwd.getpwuid(os.getuid()).pw_name != 'ntc' or socket.gethostname() != 'laptop':
        raise BridgeError('This helper belongs to the approved laptop account', 403)
    if request.get('schema_version') != 2 or 'peer' in request:
        raise BridgeError('Expected native lifecycle request')
    result = runner(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                     '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
                     '-o', 'KbdInteractiveAuthentication=no', '-o', 'ConnectTimeout=8',
                     OPERATOR, '/usr/local/sbin/agent-babel-trusted-session', PEER],
                    input=json.dumps(request), capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise BridgeError('Private operator enrollment failed; preserve the native request', 503)
    return json.loads(result.stdout)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('setup', 'check', 'tool'))
    parser.add_argument('--tool', choices=sorted(TOOLS))
    args = parser.parse_args()
    try:
        config = Path.home()/'.config/255bits/agent-babel/trusted-account.json'
        private(config)
        if config.stat().st_size > 4096 or json.loads(config.read_text()) != {'schema_version': 1, 'peer': PEER}:
            raise BridgeError('Invalid laptop account configuration')
        ctx = context('codex')
        helper = Helper(config.parent/'automatic-instances', PEER)
        bind_reviewed(helper, config.parent, ctx)
        if args.action == 'setup':
            path, credential, request = helper.prepare(ctx)
            try:
                result = helper.verify(path, credential)
            except HTTPError as error:
                if error.code not in (401, 403):
                    raise
                submit(request)
                result = helper.verify(path, credential)
        else:
            path = helper.path(ctx)
            if not (path/'token').exists():
                raise BridgeError('Run babel-session setup for this native session first')
            if args.action == 'check':
                result = helper.verify(path, path/'token')
            else:
                if not args.tool:
                    raise BridgeError('Select a helper tool')
                raw = __import__('sys').stdin.buffer.read(65537)
                if len(raw) > 65536:
                    raise BridgeError('Tool input too large')
                result = helper.call(path, args.tool, json.loads(raw or b'{}'))
        print(json.dumps(result))
        return 0
    except (BridgeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('Babel laptop connection failed: '+type(error).__name__+'. Private session files are retained.', file=__import__('sys').stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
