"""Automatic account receiver, started by the existing trusted Codex hook.

No session registry, systemd units, enrollment, lifecycle renewal or ACKs. Native
loaded-thread discovery selects only already-created exact-context mailboxes.
Same-UID local processes remain trusted, as with the existing account helper.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from account_session_helper import Helper, private
from babel.account_bootstrap import local_key, UUID, OPENCODE_SESSION
from babel.core import identifier
from babel.native_receiver import Native, NativeUnavailable, NativeRejected

COORDINATORS = {'bits255.dots.ada_20261002', 'bits255.grokbot.grok_20261002'}
ROTATION = ('resume-token', 'resume-event.json', 'rotation-journal.json', 'token.pending')
POLL_SECONDS = 20


class Deferred(RuntimeError):
    """Not enrolled, rotating, already watched or unavailable; no mutation."""


class Quarantined(RuntimeError):
    """Uncertain prior intent must be reconciled; never submit it again."""


def read_json(path, limit=1048576):
    private(path)
    if path.stat().st_size > limit:
        raise ValueError('Account wake metadata too large')
    return json.loads(path.read_text())


def write_json(path, value):
    private(path.parent, True)
    if path.exists() or path.is_symlink():
        private(path)
    fd, temporary = tempfile.mkstemp(prefix='.account-wake-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def locked(path, *, create=True):
    if path.exists() or path.is_symlink():
        private(path)
    flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT if create else 0)
    fd = os.open(path, flags, 0o600)
    try:
        private(path)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Deferred('Existing receiver owns this mailbox') from None
        yield fd
    finally:
        os.close(fd)


def account(path):
    path = Path(path).absolute()
    cfg = read_json(path, 4096)
    if set(cfg) != {'schema_version', 'peer'} or cfg['schema_version'] != 1:
        raise ValueError('Invalid account configuration')
    root = path.parent / 'automatic-instances'
    private(root, True)  # Never create an identity directory while discovering.
    helper = Helper(root, cfg['peer'])
    return path.parent, helper


class Mailbox:
    def __init__(self, config_root, helper, sid, *, client='codex'):
        if client not in ('codex', 'claude', 'opencode', 'grokbot'):
            raise ValueError('Unsupported native mailbox client')
        if not (OPENCODE_SESSION if client == 'opencode' else UUID).fullmatch(sid):
            raise ValueError('Invalid native context')
        self.root, self.helper, self.sid, self.client = config_root, helper, sid, client
        key = local_key(helper.peer, {'client': client, 'native_id': sid})
        self.path = helper.root / (client + '-auto_' + key)
        self.participant = 'bits255.' + client + '.auto_' + key
        mapping = config_root / 'native-bindings.json'
        legacy = None
        if mapping.exists() or mapping.is_symlink():
            data = read_json(mapping, 16384)
            if set(data) != {'schema_version', 'bindings'} or data['schema_version'] != 1:
                raise ValueError('Invalid reviewed native map')
            legacy = data['bindings'].get(client + ':' + sid)
        if legacy is not None:
            if not isinstance(legacy, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,23}', legacy):
                raise ValueError('Invalid reviewed native mapping')
            self.path = config_root / 'instances' / (client + '-' + legacy)
            private(self.path, True)
            manifest = read_json(self.path / 'enrollment.json', 4096)
            self.participant = identifier(manifest['participant'])
            expected = {'peer': helper.peer, 'client': client, 'native_id': sid,
                        'participant': self.participant}
            if read_json(self.path / 'account-native-binding.json', 4096) != expected:
                raise ValueError('Reviewed native binding mismatch')
        else:
            if not self.path.exists():
                raise Deferred('Session bootstrap pending')
            private(self.path, True)
            manifest = read_json(self.path / 'trusted-enrollment.json', 4096)
            if manifest.get('native_id') != sid:
                raise ValueError('Native mailbox mismatch')
        if manifest.get('client') != client:
            raise ValueError('Mailbox client mismatch')
        self.digest = manifest['sha256']
        self.check()

    def check(self):
        if any((self.path / name).exists() or (self.path / name).is_symlink() for name in ROTATION):
            raise Deferred('Native credential rotation pending')
        private(self.path / 'token')
        if hashlib.sha256((self.path / 'token').read_text().strip().encode()).hexdigest() != self.digest:
            raise Deferred('Native credential changed')

    def call(self, name, args):
        self.check()
        # Explicit committed credential prevents verification/rotation in a poll.
        result = self.helper.call(self.path, name, args, credential=self.path / 'token',
                                  expected_digest=self.digest)
        self.check()
        return result


def fingerprint(row):
    names = ('id', 'source', 'recipient', 'conversation_id', 'text', 'created', 'approved', 'reply_to', 'root_id')
    return hashlib.sha256(json.dumps({name: row.get(name) for name in names}, sort_keys=True).encode()).hexdigest()


def notice(box, mid, claim):
    import shlex
    if box.client == 'opencode':
        return ('Babel mailbox notification for ' + box.participant + '. Message ID: ' + mid +
                '. Reserved claim ID: ' + claim + '. Renew this EXACT claim using your native babel tool, '
                'operation claim_message with arguments containing message_id and claim_id. If claimed is false, skip it. '
                'Read authenticated sender, acknowledge receipt through operation acknowledge_message with the same claim ID, '
                'then handle under the existing Ember/Ada coordinator rule and permissions. Reply in the same '
                'conversation with reply_to. Receipt is not task completion. No filesystem helper/setup is needed.')
    helper = str(Path(__file__).resolve().parent.parent / 'account_session_helper.py')
    command = shlex.join([sys.executable, helper, 'tool', '--client', box.client, '--account-file',
                          str(box.root / 'trusted-account.json'), '--native-session', box.sid,
                          '--tool', 'claim_message'])
    return ('Babel mailbox notification for ' + box.participant + '. Message ID: ' + mid +
            '. Reserved claim ID: ' + claim + '. Renew this EXACT claim using ' + command +
            ', with message_id and claim_id as JSON on stdin. If claimed is false, skip it. '
            'Read authenticated sender, acknowledge receipt with the same claim ID, then handle '
            'under the existing Ember/Ada coordinator rule and permissions. Reply in the same '
            'conversation with reply_to. Receipt is not task completion.')


class Delivery:
    def __init__(self, box, native, *, state_path=None):
        self.box, self.native = box, native
        self.path = state_path or box.path / 'account-wake-state.json'
        self.state = {'schema_version': 1, 'native_id': box.sid,
                      'participant': box.participant, 'submissions': {}}
        if self.path.exists() or self.path.is_symlink():
            state = read_json(self.path)
            if set(state) != set(self.state) or any(state[k] != self.state[k] for k in
                                                   ('schema_version', 'native_id', 'participant')):
                raise Quarantined('Retain mismatched delivery ledger')
            if not isinstance(state['submissions'], dict) or len(state['submissions']) > 8192:
                raise Quarantined('Delivery ledger capacity reached')
            for mid, item in state['submissions'].items():
                identifier(mid)
                claim = 'wake_' + hashlib.sha256((box.participant + ':' + box.sid + ':' + mid).encode()).hexdigest()
                if (not isinstance(item, dict) or set(item) != {'state', 'claim_id', 'fingerprint'}
                        or item.get('state') != 'accepted' or item.get('claim_id') != claim
                        or not re.fullmatch(r'[a-f0-9]{64}', str(item.get('fingerprint')))):
                    raise Quarantined('Uncertain native delivery requires reconciliation')
            self.state = state
        self.previous = set()
        for name in ('wake-state.pending.json', 'wake-state.json.pending',
                     'relay-session-wake-state.pending.json', 'account-wake-state.pending.json'):
            if (box.path / name).exists() or (box.path / name).is_symlink():
                raise Quarantined('Retain interrupted watcher state for reconciliation')
        for name in ('wake-state.json', 'relay-session-wake-state.json'):
            path = box.path / name
            if not path.exists() and not path.is_symlink():
                continue
            old = read_json(path)
            if old.get('thread') != box.sid or old.get('participant', box.participant) != box.participant:
                raise Quarantined('Retain prior watcher binding for reconciliation')
            for mid, item in old.get('submissions', {}).items():
                if item.get('state') != 'accepted':
                    raise Quarantined('Prior watcher outcome uncertain')
                self.previous.add(identifier(mid))
            self.previous.update(identifier(mid) for mid in old.get('notified', []))

    def persist(self):
        write_json(self.path, self.state)

    def step(self):
        box = self.box
        deadline = time.monotonic() + 30
        metadata = self.native.metadata(box.sid)
        routes = {(row['recipient'], row['conversation_id']) for row in
                  box.call('list_contacts', {})['contacts'] if row['recipient'] in COORDINATORS}
        submitted, cursor = 0, 0
        for _ in range(20):
            if time.monotonic() >= deadline:
                return submitted
            rows = box.call('receive_messages', {'limit': 50, 'after': cursor})['messages']
            if not isinstance(rows, list) or len(rows) > 50:
                raise ValueError('Invalid inbox page')
            for row in rows:
                if time.monotonic() >= deadline:
                    return submitted
                seq = row.get('seq')
                if type(seq) is not int or seq <= cursor or row.get('recipient') != box.participant:
                    raise ValueError('Inbox context mismatch')
                cursor = seq
                mid = identifier(row['id'])
                if mid in self.previous or mid in self.state['submissions']:
                    continue
                if (row['source'], row['conversation_id']) not in routes:
                    continue
                if len(self.state['submissions']) >= 8192:
                    raise Quarantined('Delivery ledger full; retain history')
                self.native.metadata(box.sid)  # No claiming closed threads.
                claim = 'wake_' + hashlib.sha256((box.participant + ':' + box.sid + ':' + mid).encode()).hexdigest()
                fp = fingerprint(row)
                item = {'state': 'reserving', 'claim_id': claim, 'fingerprint': fp}
                self.state['submissions'][mid] = item
                self.persist()  # Durable before either mutating boundary.
                reserved = box.call('claim_message', {'message_id': mid, 'claim_id': claim})
                if type(reserved.get('claimed')) is not bool:
                    raise Quarantined('Ambiguous claim outcome')
                if not reserved['claimed']:
                    del self.state['submissions'][mid]
                    self.persist()
                    continue
                expires = reserved.get('expires')
                if (reserved.get('claim_id') != claim or fingerprint(reserved['message']) != fp
                        or type(expires) not in (int, float) or not math.isfinite(expires)
                        or expires < time.time() + 20):
                    raise Quarantined('Reserved claim changed')
                latest = box.call('message_status', {'message_id': mid})['message']
                if fingerprint(latest) != fp:
                    raise Quarantined('Reserved message changed')
                if latest['status'] == 'acknowledged':
                    del self.state['submissions'][mid]
                    self.persist()
                    continue
                if latest['status'] != 'queued' or reserved['expires'] < time.time() + 20:
                    raise Quarantined('Reserved message unavailable')
                box.check()
                item['state'] = 'submitting'
                self.persist()
                try:
                    self.native.queue(box.sid, metadata['cwd'], notice(box, mid, claim), reserved['expires'])
                except NativeRejected:
                    # A native actor may become busy after discovery. This
                    # explicit pre-admission rejection permits a later retry;
                    # the stable claim remains reserved, never acknowledged.
                    del self.state['submissions'][mid]
                    self.persist()
                    return submitted
                item['state'] = 'accepted'
                self.persist()
                submitted += 1
                if submitted >= 3:
                    return submitted
            if len(rows) < 50:
                return submitted
        return submitted


class Receiver:
    def __init__(self, account_file, socket_path, *, workers=4, client='codex', native_factory=Native):
        self.root, self.helper = account(account_file)
        self.client, self.native_factory = client, native_factory
        self.native = native_factory(socket_path)
        self.status_file = self.root / ('account-wake-status.json' if client == 'codex' else client + '-account-wake-status.json')
        self.pool = ThreadPoolExecutor(max_workers=workers)
        self.workers = workers
        self.futures, self.due, self.statuses = {}, {}, {}

    def deliver(self, sid):
        box = Mailbox(self.root, self.helper, sid, client=self.client)
        with ExitStack() as stack:
            stack.enter_context(locked(box.path / 'account-wake.lock'))
            # Cooperate with installed old watchers; don't race their claims.
            for name in ('wake.lock', 'relay-session-wake.lock'):
                if (box.path / name).exists() or (box.path / name).is_symlink():
                    stack.enter_context(locked(box.path / name, create=False))
            native = self.native_factory(self.native.path, self.native.identity)
            return Delivery(box, native).step()

    def tick(self):
        # Retry existing native evidence even while a new mailbox awaits auth.
        # The opt-in transport never creates lifecycle activity from this poll.
        from babel.account_enrollment import ensure_enrollment
        ensure_enrollment(self.root / 'trusted-account.json')
        loaded = self.native.loaded()  # Only loaded exact native IDs; no disk scan/adoption.
        now = time.monotonic()
        changed = False
        for sid, future in list(self.futures.items()):
            if future.done():
                try:
                    future.result()
                    state = 'watching'
                except Deferred:
                    state = 'waiting'
                except Quarantined:
                    state = 'quarantined'
                except Exception:
                    state = 'unavailable'
                if self.statuses.get(sid) != state:
                    print(json.dumps({'native_session': sid, 'receiver': state}), flush=True)
                    changed = True
                self.statuses[sid] = state
                self.due[sid] = now + POLL_SECONDS
                del self.futures[sid]
        active = set(loaded)
        for sid in set(self.due) - active - set(self.futures):
            self.due.pop(sid, None)
            self.statuses.pop(sid, None)
            changed = True
        # Submit only available worker slots. A slow inbox cannot monopolize a
        # whole cycle or build an unbounded executor backlog.
        available = self.workers - len(self.futures)
        eligible = [sid for sid in loaded if sid not in self.futures and self.due.get(sid, 0) <= now]
        for sid in sorted(eligible, key=lambda sid: (self.due.get(sid, 0), sid))[:max(0, available)]:
            self.futures[sid] = self.pool.submit(self.deliver, sid)
        if changed:
            write_json(getattr(self, 'status_file', self.root / 'account-wake-status.json'),
                       {'sessions': self.statuses, 'observed_at': time.time()})

    def close(self):
        self.pool.shutdown(wait=True)


def ensure_receiver(account_file):
    """Local-only trusted hook seam; no new registration, account or service.

    Only the existing approved account's canonical config can auto-start it.
    Synthetic installs and arbitrary project account files cannot start a worker.
    """
    account_file = Path(account_file).absolute()
    canonical = Path.home() / '.config/255bits/agent-babel/trusted-account.json'
    if account_file != canonical:
        return False
    root, _ = account(account_file)
    socket_path = Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex'))) / 'app-server-control/app-server-control.sock'
    try:
        private(socket_path.parent, True)
        info = socket_path.stat()
        key = [info.st_dev, info.st_ino]
    except OSError:
        return False
    startup = root / 'account-wake-start.lock'
    try:
        with locked(startup) as fd:
            try:
                with locked(root / 'account-wake-runtime.lock'):
                    pass
            except Deferred:
                receipt = root / 'account-wake-runtime.json'
                if receipt.exists() and read_json(receipt, 4096).get('socket') == key:
                    return True
            script = Path(__file__).resolve().parent.parent / 'account_wake.py'
            env = os.environ.copy()
            env.pop('CODEX_THREAD_ID', None)
            env.pop('BABEL_SESSION_TOKEN', None)
            subprocess.Popen([sys.executable, str(script), '--account-file', str(account_file),
                              '--socket', str(socket_path), '--startup-fd', str(fd)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, pass_fds=(fd,), env=env,
                             cwd=str(script.parent))
            return True
    except Deferred:
        return True  # Another trusted start already launched the receiver.


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account-file', required=True, type=Path)
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--startup-fd', required=True, type=int)
    args = parser.parse_args()
    receiver = None
    try:
        root, _ = account(args.account_file)
        startup = root / 'account-wake-start.lock'
        private(startup)
        if os.fstat(args.startup_fd).st_ino != startup.stat().st_ino:
            raise ValueError('Receiver startup context mismatch')
        # A previous runtime receiver notices a replaced/stopped native endpoint
        # and exits. One inherited startup lock serializes automatic takeover.
        deadline = time.monotonic() + 120
        while True:
            try:
                with locked(root / 'account-wake-runtime.lock'):
                    receiver = Receiver(args.account_file, args.socket)
                    receiver.native.loaded()
                    identity = receiver.native.identity
                    write_json(root / 'account-wake-runtime.json',
                               {'pid': os.getpid(), 'socket': [identity['socket_device'], identity['socket_inode']]})
                    os.close(args.startup_fd)
                    while True:
                        try:
                            receiver.tick()
                        except Exception:
                            # Retrying a metadata read is safe. Retire when the
                            # native runtime/endpoint changes; a new trusted start
                            # automatically takes over using the singleton lock.
                            current = args.socket.stat()
                            start = Path('/proc', str(identity['pid']), 'stat').read_text().rsplit(')', 1)[1].split()[19]
                            if (current.st_dev != identity['socket_device'] or
                                    current.st_ino != identity['socket_inode'] or start != identity['start']):
                                return
                        time.sleep(2)
            except Deferred:
                if time.monotonic() >= deadline:
                    return
                time.sleep(.25)
    except (Exception, KeyboardInterrupt):
        # No URLs, credentials, peer text or native private response bodies.
        return
    finally:
        if receiver is not None:
            receiver.close()
