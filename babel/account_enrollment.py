"""Opt-in account-local lifecycle metadata drain over the existing owner SSH path.

Never reads tokens/transcripts, manufactures native events, changes accounts or
recipient grants, or runs a service/timer. Native integrations schedule bounded
passes. The private operator remains the sole enrollment authority.
"""
import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import selectors
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

from account_session_helper import private
from .account_bootstrap import local_key, PEERS, UUID, NATIVE, OPENCODE_SESSION
from .core import BridgeError
from .native_lifecycle import event_key

TRANSPORT_FILE = 'account-enrollment-transport.json'
STATE_DIRECTORY = 'account-enrollment'
CLIENTS = frozenset(('codex', 'claude', 'cursor', 'opencode', 'grokbot'))
FOLDER = re.compile(r'(codex|claude|cursor|opencode|grokbot)-auto_[a-f0-9]{32}\Z')
SHA = re.compile(r'[a-f0-9]{64}\Z')
MAX_FILES = 8192
MAX_FOLDERS = 4096
SCAN_FOLDERS = 16
SCAN_FILES = 32768
BATCH = 4
MAX_RECORDS = 32768
IDLE = 86400
SCAN_DELAY = 20
PASS_SECONDS = 45
SSH_SECONDS = 10
SSH = ('/usr/bin/ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
       '-o', 'KbdInteractiveAuthentication=no', '-o', 'NumberOfPasswordPrompts=0',
       '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1',
       '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'ClearAllForwardings=yes',
       '-o', 'PermitLocalCommand=no', '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none',
       '-o', 'HostName=159.195.17.119', '-o', 'User=root', '-o', 'Port=22',
       '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'RemoteCommand=none',
       '-o', 'SendEnv=-*', '-o', 'LogLevel=ERROR',
       'root@159.195.17.119', '/usr/local/sbin/agent-babel-trusted-session')


class TransportUnavailable(RuntimeError):
    """Connection outcome is uncertain; replay the exact event after backoff."""


class OperatorRejected(RuntimeError):
    """No verified acceptance. Retain evidence and isolate this item's retry."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(request):
    return hashlib.sha256(canonical(request).encode()).hexdigest()


def read_bytes(path, limit=4096):
    path = Path(path)
    private(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > limit):
            raise BridgeError('Owned bounded metadata required')
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise BridgeError('Metadata capacity reached')
        return data
    finally:
        os.close(fd)


def read_json(path, limit=4096):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError('Duplicate metadata key')
            result[key] = value
        return result
    return json.loads(read_bytes(path, limit), object_pairs_hook=pairs)


def atomic(path, value):
    path = Path(path)
    private(path.parent, True)
    if path.exists() or path.is_symlink():
        private(path)
    fd, temporary = tempfile.mkstemp(prefix='.enrollment-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Configuration:
    def __init__(self, account_file):
        who = pwd.getpwuid(os.getuid())
        self.home = Path(who.pw_dir)
        expected = self.home / '.config/255bits/agent-babel/trusted-account.json'
        self.account_file = Path(account_file).absolute()
        if self.account_file != expected:
            raise BridgeError('Canonical owning account required')
        self.root = expected.parent
        self.enabled = False
        transport = self.root / TRANSPORT_FILE
        # Default disabled, including accounts with no integration installed.
        if not transport.exists() and not transport.is_symlink():
            return
        private(self.root, True)
        config = read_json(expected)
        if (not isinstance(config, dict) or set(config) != {'schema_version', 'peer'}
                or type(config['schema_version']) is not int or config['schema_version'] != 1):
            raise BridgeError('Invalid trusted account metadata')
        self.peer = who.pw_name + '@' + socket.gethostname()
        if self.peer not in PEERS or config['peer'] != self.peer:
            raise BridgeError('Owning UNIX account/host mismatch')
        data = read_json(transport)
        if (not isinstance(data, dict) or set(data) != {'schema_version', 'enabled', 'transport'}
                or type(data['schema_version']) is not int or data['schema_version'] != 1
                or type(data['enabled']) is not bool or data['transport'] != 'pinned-ssh-operator'):
            raise BridgeError('Explicit private operator transport required')
        self.enabled = data['enabled']
        self.instances = self.root / 'automatic-instances'
        self.state = self.root / STATE_DIRECTORY

    def prepare_state(self):
        self.state.mkdir(mode=0o700, exist_ok=True)
        private(self.state, True)


def ssh_environment(home):
    # SSH may use the owner's existing agent/default keys in place. Do not propagate
    # Babel/model/cloud credentials via a broad user SendEnv rule.
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
    if os.environ.get('SSH_AUTH_SOCK'):
        env['SSH_AUTH_SOCK'] = os.environ['SSH_AUTH_SOCK']
    return env


def bounded_process(argv, data, *, env, timeout):
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, cwd=env['HOME'])
    streams, output = selectors.DefaultSelector(), bytearray()
    deadline = time.monotonic() + timeout
    seen = 0
    try:
        process.stdin.write(data)
        process.stdin.close()
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            streams.register(stream, selectors.EVENT_READ)
        while streams.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                raise TransportUnavailable('Private transport timeout')
            for key, _ in streams.select(min(left, .5)):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    streams.unregister(key.fileobj)
                    continue
                seen += len(chunk)
                if seen > 16384:
                    raise TransportUnavailable('Private transport output capacity reached')
                if key.fileobj is process.stdout:
                    output.extend(chunk)
                    if len(output) > 4096:
                        raise OperatorRejected('Unverified operator reply')
        returncode = process.wait(timeout=max(.01, deadline - time.monotonic()))
        if returncode == 255:
            raise TransportUnavailable('Private transport unavailable')
        if returncode:
            raise OperatorRejected('Private operator rejected evidence')
        return bytes(output)
    except (subprocess.SubprocessError, OSError):
        raise TransportUnavailable('Private transport unavailable') from None
    finally:
        streams.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


class SSHTransport:
    def __init__(self, home):
        self.home = home

    def submit(self, peer, request, timeout=SSH_SECONDS):
        if peer not in PEERS:
            raise BridgeError('Unapproved private account')
        raw = bounded_process([*SSH, peer], (canonical(request) + '\n').encode(),
                              env=ssh_environment(self.home), timeout=timeout)
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError):
            raise OperatorRejected('Unverified operator reply') from None


def validate_request(peer, folder, path, request, now):
    required = {'schema_version', 'client', 'native_id', 'sha256', 'event_id', 'kind', 'observed_at'}
    if (not isinstance(request, dict) or set(request) - {'existing_participant'} != required
            or type(request['schema_version']) is not int or request['schema_version'] != 2):
        raise BridgeError('Native lifecycle metadata required')
    client, sid, event = request['client'], request['native_id'], request['event_id']
    pattern = OPENCODE_SESSION if client == 'opencode' else NATIVE if client == 'cursor' else UUID
    if (client not in CLIENTS or not isinstance(sid, str) or not pattern.fullmatch(sid)
            or (client in ('codex', 'claude', 'grokbot') and sid != sid.lower())
            or not isinstance(event, str) or not NATIVE.fullmatch(event)
            or request['kind'] not in ('bootstrap', 'turn', 'resume')
            or not isinstance(request['sha256'], str) or not SHA.fullmatch(request['sha256'])
            or request['sha256'] == '0' * 64):
        raise BridgeError('Invalid native lifecycle metadata')
    observed = request['observed_at']
    if type(observed) not in (int, float) or not math.isfinite(observed) or not 0 < observed <= now:
        raise BridgeError('Invalid native observation time')
    if folder != client + '-auto_' + local_key(peer, request) or path.name != event_key(event)[7:] + '.json':
        raise BridgeError('Native metadata path mismatch')
    # Adopted mappings retain their separate reviewed manual operator path.
    # Their exact granted conversation is not present in native event metadata.
    if 'existing_participant' in request:
        raise BridgeError('Reviewed legacy operator mapping required')
    return request


def accepted_reply(peer, request, result, now):
    key = local_key(peer, request)
    if (not isinstance(result, dict) or set(result) != {'participant', 'conversation', 'generation', 'state', 'deadline'}
            or result['participant'] != 'bits255.' + request['client'] + '.auto_' + key
            or result['conversation'] != 'report_auto_' + key + '_ember'
            or result['state'] != 'active' or type(result['generation']) is not int
            or not 1 <= result['generation'] < 2**63 or type(result['deadline']) not in (int, float)
            or not math.isfinite(result['deadline']) or not now < result['deadline'] <= now + IDLE + 60):
        raise OperatorRejected('Unverified private operator acceptance')


def receipt(path, request):
    # Preserve the exact native evidence. Only a verified acceptance reaches here.
    if read_json(path) != request:
        raise BridgeError('Native evidence changed before receipt')
    target = path.with_suffix('.receipt')
    value = digest(request) + '\n'
    if target.exists() or target.is_symlink():
        if read_bytes(target, 128) != value.encode():
            raise BridgeError('Retain conflicting metadata receipt')
        return
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, value.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class Drainer:
    def __init__(self, config, *, transport=None, clock=time.time, monotonic=time.monotonic):
        self.config, self.clock, self.monotonic = config, clock, monotonic
        self.transport = transport or SSHTransport(config.home)
        self.counts = {'accepted': 0, 'receipts': 0, 'rejected': 0, 'invalid': 0, 'stale': 0}

    def state(self):
        path = self.config.state / 'ledger.sqlite3'
        if path.exists() or path.is_symlink():
            private(path)
        else:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode)
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise BridgeError('Owned private enrollment ledger required')
        finally:
            os.close(fd)
        db = sqlite3.connect(path)
        db.execute('PRAGMA busy_timeout=1000')
        db.execute('CREATE TABLE IF NOT EXISTS events(folder TEXT,event_id TEXT,fingerprint TEXT,state TEXT,attempts INTEGER,retry_at REAL,PRIMARY KEY(folder,event_id))')
        db.execute('CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT)')
        return db

    def setting(self, db, key, default='0'):
        row = db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return row[0] if row else default

    def update(self, db, key, value):
        db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)', (key, str(value)))

    def scan(self, db, deadline):
        root, now = self.config.instances, self.clock()
        self.rr_scanned, self.rr_ready = [], set()
        if not root.exists():
            return []
        private(root, True)
        names, hints = [], {}
        for entry in os.scandir(root):
            if FOLDER.fullmatch(entry.name):
                names.append(entry.name)
                try:
                    if entry.is_dir(follow_symlinks=False):
                        hints[entry.name] = (root / entry.name / 'lifecycle-events').lstat().st_mtime_ns
                except OSError:
                    pass
                if len(names) > MAX_FOLDERS:
                    raise BridgeError('Account metadata folder capacity reached')
        names.sort()
        cursor = self.setting(db, 'cursor', '')
        ordered = [name for name in names if name > cursor] + [name for name in names if name <= cursor]
        rr = ordered[:SCAN_FOLDERS // 2]
        recent = sorted((name for name in names if name not in rr), key=lambda name: hints.get(name, 0), reverse=True)[:SCAN_FOLDERS // 2]
        self.recent = set(recent)
        self.hints = hints
        groups, examined = [], {'recent': 0, 'rr': 0}
        # Recent mtime is intake priority only; observed_at and exact native
        # evidence remain mandatory. Reserve intake capacity for both cohorts.
        for name in recent + rr:
            category = 'recent' if name in self.recent else 'rr'
            if self.monotonic() >= deadline:
                break
            if category == 'rr':
                self.rr_scanned.append(name)
            folder = root / name
            try:
                private(folder, True)
                spool = folder / 'lifecycle-events'
                private(spool, True)
            except (OSError, BridgeError):
                self.counts['invalid'] += 1
                continue
            candidates, bootstrap_pending, bootstrap_accepted, complete, count = [], None, False, True, 0
            for entry in os.scandir(spool):
                if not entry.name.endswith('.json'):
                    continue
                count += 1
                examined[category] += 1
                if count > MAX_FILES or examined[category] > SCAN_FILES // 2 or self.monotonic() >= deadline:
                    complete = False
                    break
                path = spool / entry.name
                try:
                    request = validate_request(self.config.peer, name, path, read_json(path), now)
                    fp = digest(request)
                    row = db.execute('SELECT fingerprint,state,attempts,retry_at FROM events WHERE folder=? AND event_id=?', (name, request['event_id'])).fetchone()
                    if row and row[0] != fp:
                        self.counts['invalid'] += 1
                        continue  # Immutable native event changed: never forward or ACK it.
                    target = path.with_suffix('.receipt')
                    if target.exists() or target.is_symlink():
                        if read_bytes(target, 128).strip() != fp.encode():
                            raise BridgeError('Metadata receipt mismatch')
                        bootstrap_accepted |= request['kind'] in ('bootstrap', 'resume')
                        continue
                    if row and row[1] == 'accepted':
                        receipt(path, request)
                        self.counts['receipts'] += 1
                        bootstrap_accepted |= request['kind'] in ('bootstrap', 'resume')
                        continue
                    if now - request['observed_at'] >= IDLE:
                        self.counts['stale'] += 1
                        continue  # Not accepted: no .receipt, server call or revival.
                    item = {'folder': name, 'path': path, 'request': request, 'fingerprint': fp,
                            'retry_at': row[3] if row else 0, 'attempts': row[2] if row else 0}
                    candidates.append(item)
                    candidates.sort(key=lambda x: (x['request']['observed_at'],
                                                   {'bootstrap': 0, 'resume': 1, 'turn': 2}[x['request']['kind']],
                                                   x['request']['event_id']))
                    del candidates[BATCH:]
                    if request['kind'] == 'bootstrap':
                        bootstrap_pending = item
                except (BridgeError, OSError, ValueError, TypeError, KeyError):
                    self.counts['invalid'] += 1
            # Do not submit a partially indexed folder out of event order.
            if not complete:
                self.counts['invalid'] += 1
                continue
            if bootstrap_pending is not None:
                candidates = [bootstrap_pending] + [item for item in candidates if item is not bootstrap_pending]
            elif not bootstrap_accepted:
                # A scan/tool cannot create a session from a bare turn. A
                # genuinely fresh native resume remains valid evidence after
                # its original bootstrap aged out; never relabel either event.
                candidates = [item for item in candidates if item['request']['kind'] == 'resume']
            if candidates:
                groups.append(candidates)
                if category == 'rr':
                    self.rr_ready.add(name)
        db.commit()
        return groups

    def run(self):
        if not self.config.enabled:
            return {'state': 'disabled'}
        self.config.prepare_state()
        db = self.state()
        try:
            now = self.clock()
            if now < float(self.setting(db, 'high_water')):
                raise BridgeError('Account lifecycle clock moved backwards')
            self.update(db, 'high_water', now)
            if now < float(self.setting(db, 'transport_retry_at')):
                return {'state': 'backoff', **self.counts}
            end = self.monotonic() + PASS_SECONDS
            groups = self.scan(db, end - SSH_SECONDS)
            groups.sort(key=lambda g: g[0]['folder'])
            submit_cursor = self.setting(db, 'submit_cursor', '')
            groups = ([g for g in groups if g[0]['folder'] > submit_cursor] +
                      [g for g in groups if g[0]['folder'] <= submit_cursor])
            recent = sorted((g for g in groups if g[0]['folder'] in getattr(self, 'recent', set())),
                            key=lambda g: self.hints.get(g[0]['folder'], 0), reverse=True)
            ordinary = [g for g in groups if g not in recent]
            groups = recent[:BATCH // 2] + ordinary + recent[BATCH // 2:]
            attempted, transport_retry, considered = 0, 0, set()
            # One event per session per round; a denied/old session cannot own
            # the batch. Its following events wait behind that exact head.
            while groups and attempted < BATCH and self.monotonic() < end:
                next_round = []
                for group in groups:
                    if attempted >= BATCH or self.monotonic() >= end:
                        break
                    item, rest = group[0], group[1:]
                    request, folder = item['request'], item['folder']
                    considered.add(folder)
                    if item['retry_at'] > self.clock():
                        continue
                    try:
                        current = Configuration(self.config.account_file)
                        unchanged = read_json(item['path']) == request
                    except (BridgeError, OSError, ValueError, TypeError):
                        self.counts['invalid'] += 1
                        continue
                    if not current.enabled or current.peer != self.config.peer:
                        groups = []
                        break  # Owner opt-out stops later submissions in this pass.
                    if not unchanged:
                        self.counts['invalid'] += 1
                        continue
                    count = db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
                    existing = db.execute('SELECT 1 FROM events WHERE folder=? AND event_id=?',
                                          (folder, request['event_id'])).fetchone()
                    if count >= MAX_RECORDS and not existing:
                        self.counts['rejected'] += 1
                        continue
                    attempts = item['attempts'] + 1
                    retry = self.clock() + min(300, SCAN_DELAY * 2**min(attempts - 1, 4))
                    db.execute('INSERT OR REPLACE INTO events VALUES(?,?,?,?,?,?)',
                               (folder, request['event_id'], item['fingerprint'], 'pending', attempts, retry))
                    self.update(db, 'submit_cursor', folder)
                    db.commit()  # Durable intent/backoff before SSH; exact replay after ambiguity.
                    attempted += 1
                    try:
                        result = self.transport.submit(self.config.peer, request,
                                                       timeout=min(SSH_SECONDS, max(.01, end - self.monotonic())))
                        accepted_reply(self.config.peer, request, result, self.clock())
                    except TransportUnavailable:
                        failures = int(self.setting(db, 'transport_failures')) + 1
                        transport_retry = self.clock() + min(300, SCAN_DELAY * 2**min(failures - 1, 4))
                        self.update(db, 'transport_failures', failures)
                        self.update(db, 'transport_retry_at', transport_retry)
                        self.counts['rejected'] += 1
                        groups = []
                        break
                    except (OperatorRejected, BridgeError, OSError, ValueError):
                        self.counts['rejected'] += 1
                        continue
                    db.execute('UPDATE events SET state=\'accepted\' WHERE folder=? AND event_id=?', (folder, request['event_id']))
                    self.update(db, 'transport_failures', 0)
                    self.update(db, 'transport_retry_at', 0)
                    db.commit()  # Accepted proof precedes receipt publication.
                    self.counts['accepted'] += 1
                    try:
                        receipt(item['path'], request)
                        self.counts['receipts'] += 1
                    except (BridgeError, OSError, ValueError):
                        pass  # Retry only the receipt from durable accepted proof.
                    if rest:
                        next_round.append(rest)
                else:
                    groups = next_round
                    continue
                break
            # Recent intake cannot reset the historical round-robin cursor.
            # Advance through empty/considered RR folders, stopping before a
            # ready group the bounded submission pass did not reach.
            for folder in self.rr_scanned:
                if folder in self.rr_ready and folder not in considered:
                    break
                self.update(db, 'cursor', folder)
            db.commit()
            result = {'schema_version': 1, 'state': 'drained', 'next_scan_at': self.clock() + SCAN_DELAY,
                      'transport_retry_at': transport_retry, **self.counts}
            atomic(self.config.state / 'status.json', canonical(result) + '\n')
            return result
        finally:
            db.close()


def ensure_enrollment(account_file, *, fresh=False):
    """Quick native seam: schedule one bounded pass, never enroll synchronously."""
    fd = None
    try:
        config = Configuration(account_file)
        if not config.enabled:
            return False
        config.prepare_state()
        status = config.state / 'status.json'
        if status.exists() or status.is_symlink():
            data = read_json(status)
            now = time.time()
            # New real work may bypass empty-scan delay, never SSH failure backoff.
            if data.get('transport_retry_at', 0) > now or (not fresh and data.get('next_scan_at', 0) > now):
                return False
        lock = config.state / 'run.lock'
        if lock.exists() or lock.is_symlink():
            private(lock)
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        script = Path(__file__).resolve().parent.parent / 'account_enrollment.py'
        subprocess.Popen([sys.executable, str(script), '--account-file', str(config.account_file),
                          '--lock-fd', str(fd)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True, pass_fds=(fd,),
                         cwd=str(script.parent), env=ssh_environment(config.home))
        return True
    except (BridgeError, OSError, ValueError, TypeError, AttributeError):
        return False
    finally:
        if fd is not None:
            os.close(fd)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account-file', required=True)
    parser.add_argument('--lock-fd', required=True, type=int)
    args = parser.parse_args()
    try:
        config = Configuration(args.account_file)
        if not config.enabled:
            return
        path = config.state / 'run.lock'
        private(path)
        own, supplied = path.stat(), os.fstat(args.lock_fd)
        if (own.st_dev, own.st_ino) != (supplied.st_dev, supplied.st_ino):
            raise BridgeError('Native account drainer lock mismatch')
        # A caller cannot name another process's lock descriptor. The inherited
        # descriptor keeps the singleton held after the native scheduler exits.
        fcntl.flock(args.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        Drainer(config).run()
    except (BridgeError, OSError, ValueError, TypeError, sqlite3.Error, BlockingIOError):
        return  # No remote/private errors or evidence content enters model context.


if __name__ == '__main__':
    main()
