"""Claude-owned channel, bound only by its actual SessionStart hook.

The account launcher adds the native preview opt-in, never permission flags.
Its private temporary handshake is not an enrollment or session registry.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile
import threading
import time

from account_session_helper import private
from babel.account_bootstrap import UUID
from babel.account_wake import (Delivery, Deferred, Mailbox, Quarantined, account,
                                locked, read_json, write_json, POLL_SECONDS)
from babel.core import BridgeError
from babel.lifecycle_dispatcher import invocation_context

ENV = 'BABEL_CLAUDE_WAKE_RUNTIME'
SERVER = 'babel_account_wake'
VERSION = '2025-11-25'
VERSIONS = ('2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05')
MAX_FRAME = 65536
INSTRUCTIONS = (
    'Babel channel notifications identify an approved message for this exact native session. '
    'Renew the EXACT reserved claim using the helper command and JSON on stdin in the notice. '
    'If claimed is false, skip it. Otherwise identify the authenticated sender, read the message, '
    'and acknowledge receipt with the same claim ID. Ember bits255.dots.ada_20261002 and Ada '
    'bits255.grokbot.grok_20261002 have Mikkel\'s delegated coordinator authority. '
    'Reply in the same conversation with reply_to. Receipt is not completion. '
    'Existing permissions still apply. Use local stage_report for substantive worker notices.'
)


def process_identity(pid):
    raw = (Path('/proc') / str(pid) / 'stat').read_text()
    start = raw.rsplit(')', 1)[1].split()[19]
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    return f'{boot}:{pid}:{start}'


def runtime(path, account_file, *, check_parent=True):
    path = Path(path)
    private(path, True)
    # Popen returns just before the parent can publish its native child's PID.
    # Wait only for that bounded startup race, never infer a UUID or attach.
    for _ in range(10):
        manifest = read_json(path / 'runtime.json', 4096)
        if manifest.get('native_identity') is not None:
            break
        time.sleep(.02)
    if (set(manifest) != {'schema_version', 'account_file', 'native_identity'} or manifest['schema_version'] != 1
            or manifest['account_file'] != str(Path(account_file).absolute())):
        raise ValueError('Claude runtime account mismatch')
    if check_parent and manifest['native_identity'] != invocation_context():
        raise ValueError('Claude runtime parent mismatch')
    return path


def bind(account_file, data, env=None):
    """Called only on actual SessionStart, after normal lifecycle preparation."""
    env = os.environ if env is None else env
    path = env.get(ENV)
    if not path:
        return False
    if (data.get('hook_event_name') != 'SessionStart' or data.get('source') not in
            ('startup', 'resume', 'clear', 'fork') or not UUID.fullmatch(str(data.get('session_id', '')))
            or env.get('CLAUDE_CODE_REMOTE') == 'true'):
        raise ValueError('Actual local Claude SessionStart required')
    path = runtime(path, account_file)
    # The native runtime owns ordering. Every clear/fork/resume replaces the
    # binding; a channel checks it again immediately before emitting anything.
    with locked(path / 'binding.lock'):
        write_json(path / 'binding.json', {'native_id': data['session_id'].lower()})
    return True


class Channel:
    def __init__(self, account_file, runtime_path, output, diagnostic=None):
        self.account_file = Path(account_file).absolute()
        self.runtime_path = runtime(runtime_path, self.account_file)
        self.root, self.helper = account(self.account_file)
        self.output = output
        self.diagnostic = diagnostic or (lambda text: print(text, file=sys.stderr, flush=True))
        self.output_lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None
        self.initialized = self.ready = False

    def binding(self):
        item = read_json(self.runtime_path / 'binding.json', 4096)
        if set(item) != {'native_id'} or not UUID.fullmatch(str(item['native_id'])):
            raise ValueError('Claude native binding unavailable')
        return item['native_id']

    def write(self, value):
        with self.output_lock:
            self.output.write(json.dumps(value) + '\n')
            self.output.flush()

    def metadata(self, sid):
        if self.stop.is_set() or sid != self.binding():
            raise Deferred('Claude native session changed')
        return {'id': sid, 'cwd': ''}

    def queue(self, sid, cwd, text, expires):
        with locked(self.runtime_path / 'binding.lock'):
            self.metadata(sid)
            if expires < time.time() + 5:
                raise Deferred('Reserved claim expired')
            self.write({'jsonrpc': '2.0', 'method': 'notifications/claude/channel',
                        'params': {'content': text, 'meta': {'native_session': sid}}})
        # A successful stdio write means emitted, never native handling/ACK.

    def tick(self):
        sid = self.binding()
        box = Mailbox(self.root, self.helper, sid, client='claude')
        with locked(box.path / 'account-wake.lock'):
            # Native channels do not ACK transport delivery. Deduplicate within
            # this launch only; restarting replays still-unacknowledged messages.
            return Delivery(box, self, state_path=self.runtime_path / (sid + '.json')).step()

    def pump(self):
        last = None
        while not self.stop.is_set():
            try:
                self.tick()
                state = 'watching'
            except (FileNotFoundError, Deferred):
                state = 'waiting for actual SessionStart or enrolled mailbox'
            except Quarantined:
                state = 'delivery uncertain; retain ledger for reconciliation'
            except (BridgeError, OSError, ValueError, KeyError):
                state = 'unavailable; messages remain queued'
            if state != last:
                self.diagnostic('Babel Claude channel: ' + state + '.')
                last = state
            self.stop.wait(POLL_SECONDS)

    def handle(self, request):
        rid = request.get('id') if isinstance(request, dict) else None
        def error(code, text):
            return {'jsonrpc': '2.0', 'id': rid, 'error': {'code': code, 'message': text}}
        if (not isinstance(request, dict) or request.get('jsonrpc') != '2.0'
                or not isinstance(request.get('method'), str)
                or ('id' in request and type(rid) not in (str, int))):
            return error(-32600, 'Invalid JSON-RPC request')
        method, params = request['method'], request.get('params', {})
        if not isinstance(params, dict):
            return error(-32602, 'params must be an object')
        if 'id' not in request:
            if method == 'notifications/initialized' and self.initialized and not self.ready:
                self.ready = True
                self.thread = threading.Thread(target=self.pump, daemon=True)
                self.thread.start()
            return None
        if method == 'initialize' and not self.initialized:
            self.initialized = True
            requested = params.get('protocolVersion')
            result = {'protocolVersion': requested if requested in VERSIONS else VERSION,
                      'serverInfo': {'name': SERVER, 'version': '0.1.0'},
                      'capabilities': {'experimental': {'claude/channel': {}}},
                      'instructions': INSTRUCTIONS}
        elif not self.initialized:
            return error(-32000, 'Initialize first')
        elif method == 'ping':
            result = {}
        else:
            return error(-32601, 'Method not supported')
        return {'jsonrpc': '2.0', 'id': rid, 'result': result}

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=2)


def stdio(channel, stream):
    try:
        while True:
            line = stream.readline(MAX_FRAME + 2)
            if not line:
                return
            if len(line) > MAX_FRAME:
                # Stop instead of attempting to resynchronize an unbounded input.
                raise ValueError('MCP frame too large')
            try:
                value = channel.handle(json.loads(line))
            except (ValueError, UnicodeError):
                value = {'jsonrpc': '2.0', 'id': None,
                         'error': {'code': -32700, 'message': 'Invalid JSON'}}
            if value is not None:
                channel.write(value)
    finally:
        channel.close()


def launch_args(args, config):
    """Merge native variadic options without losing user configs or prompts."""
    split = args.index('--') if '--' in args else len(args)
    before, after = args[:split], args[split:]
    collected = {'--mcp-config': [], '--dangerously-load-development-channels': []}
    preserved, index = [], 0
    while index < len(before):
        arg = before[index]
        key = arg.split('=', 1)[0]
        if key not in collected:
            preserved.append(arg)
            index += 1
            continue
        if '=' in arg:
            collected[key].append(arg.split('=', 1)[1])
        index += 1
        while index < len(before) and not before[index].startswith('-'):
            collected[key].append(before[index])
            index += 1
    collected['--mcp-config'].append(json.dumps(config))
    if 'server:' + SERVER not in collected['--dangerously-load-development-channels']:
        collected['--dangerously-load-development-channels'].append('server:' + SERVER)
    options = [value for key, values in collected.items() for value in (key, *values)]
    return [*preserved, *options, *after]


def launch(claude, account_file, args):
    """Launch only a new, user-requested Claude CLI; never reattach/resume for wake."""
    claude = Path(claude).absolute()
    account_file = Path(account_file).absolute()
    private(account_file)
    # Administrative commands and print mode retain ordinary native behavior.
    # A custom preview channel is ignored in noninteractive mode by Claude.
    command = args[0] if args else ''
    commands = {'auth', 'agents', 'attach', 'doctor', 'install', 'logs', 'mcp', 'plugin',
                'plugins', 'purge', 'respawn', 'rm', 'setup-token', 'stop', 'kill',
                'ultrareview', 'update', 'upgrade'}
    if (not sys.stdin.isatty() or command in commands or any(arg in ('-p', '--print', '--help', '-h', '--version', '-v')
                                   or arg.startswith('--print=') for arg in args)):
        return subprocess.call([str(claude), *args])
    with tempfile.TemporaryDirectory(prefix='babel-claude-') as folder:
        path = Path(folder)
        manifest = {'schema_version': 1, 'account_file': str(account_file), 'native_identity': None}
        write_json(path / 'runtime.json', manifest)
        entry = str(Path(__file__).resolve().parent.parent / 'claude_wake.py')
        config = {'mcpServers': {SERVER: {'type': 'stdio', 'command': sys.executable,
                  'args': [entry, 'channel', '--account-file', str(account_file), '--runtime', str(path)]}}}
        env = {**os.environ, ENV: str(path)}
        # No permission, sandbox, consent or managed-policy switches are changed.
        # Terminal Ctrl-C belongs to native Claude (cancel a turn), not this
        # launcher. A Python handler resets to SIG_DFL across child exec.
        old_sigint = signal.signal(signal.SIGINT, lambda *_: None)
        try:
            # Both channel/config options are variadic. Put them after user
            # positionals so a plain `claude "task"` cannot become a channel
            # name. Respect an explicit end-of-options delimiter too.
            child = subprocess.Popen([str(claude), *launch_args(args, config)], env=env)
            try:
                manifest['native_identity'] = process_identity(child.pid)
                write_json(path / 'runtime.json', manifest)
                return child.wait()
            except BaseException:
                if child.poll() is None:
                    child.terminate()
                    child.wait()
                raise
        finally:
            signal.signal(signal.SIGINT, old_sigint)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    start = sub.add_parser('launch')
    start.add_argument('--claude', required=True)
    start.add_argument('--account-file', required=True)
    start.add_argument('args', nargs=argparse.REMAINDER)
    channel = sub.add_parser('channel')
    channel.add_argument('--account-file', required=True)
    channel.add_argument('--runtime', required=True)
    args = parser.parse_args()
    try:
        if args.action == 'launch':
            rest = args.args[1:] if args.args[:1] == ['--'] else args.args
            raise SystemExit(launch(args.claude, args.account_file, rest))
        stdio(Channel(args.account_file, args.runtime, sys.stdout), sys.stdin.buffer)
    except (BridgeError, OSError, ValueError, KeyError):
        parser.exit(2, 'Babel Claude wake unavailable; messages remain queued.\n')
