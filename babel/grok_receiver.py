"""Grok Build notification-only control client, requiring the reviewed native patch.

Stock Grok is unsupported and fails closed. No ACP session/prompt, session/load,
session/new, remote relay, transcript subscription or owner interaction is used.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import time

from account_session_helper import private
from .account_bootstrap import UUID
from .native_receiver import NativeUnavailable, NativeRejected, require

LIMIT = 1048576
CAPABILITY = 'mailbox_notifications_v1'


class ControlSocket:
    def __init__(self, path, expected=None):
        path = Path(path)
        private(path.parent, True)
        require(not path.is_symlink())
        info = path.stat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077)
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.deadline = time.monotonic() + 5
        try:
            self.budget()
            self.socket.connect(str(path))
            pid, uid, _ = struct.unpack('3i', self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == os.getuid())
            binary = Path('/proc', str(pid), 'exe').resolve(strict=True)
            require(not any(p.is_symlink() for p in (binary, *binary.parents)))
            executable = binary.stat()
            require(stat.S_ISREG(executable.st_mode) and executable.st_uid in (0, uid) and not executable.st_mode & 0o022)
            # The native control protocol is only accepted from the owning
            # runtime pinned on first discovery; replacement retires the worker.
            self.identity = {'pid': pid, 'uid': uid,
                             'start': Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19],
                             'binary': str(binary), 'binary_inode': executable.st_ino,
                             'binary_device': executable.st_dev, 'binary_mtime': executable.st_mtime_ns,
                             'socket_inode': info.st_ino, 'socket_device': info.st_dev,
                             'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
            require(expected is None or expected == self.identity)
            self.send({'type': 'register', 'client_type': 'babel-account-wake', 'mode': 'stdio', 'capabilities': {}})
            row = self.receive()
            require(row.get('type') == 'registered' and row.get('ready') is True and
                    row.get('leader_protocol_version') == 1 and
                    row.get('leader_capabilities', {}).get('control_v1') is True and
                    row.get('leader_capabilities', {}).get(CAPABILITY) is True)
        except BaseException:
            self.socket.close()
            raise

    def budget(self):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0)
        self.socket.settimeout(remaining)

    def close(self):
        self.socket.close()

    def send(self, value):
        raw = json.dumps(value).encode()
        require(len(raw) <= LIMIT)
        self.budget()
        self.socket.sendall(struct.pack('!I', len(raw)) + raw)

    def read(self, count):
        result = bytearray()
        while len(result) < count:
            self.budget()
            chunk = self.socket.recv(count - len(result))
            require(bool(chunk))
            result.extend(chunk)
        return bytes(result)

    def receive(self):
        size = struct.unpack('!I', self.read(4))[0]
        require(0 < size <= LIMIT)
        value = json.loads(self.read(size))
        require(isinstance(value, dict))
        return value


class GrokNative:
    def __init__(self, path, identity=None):
        self.path, self.identity = Path(path), identity

    def control(self, command):
        stream = ControlSocket(self.path, self.identity)
        try:
            self.identity = stream.identity
            stream.send({'type': 'control', 'request_id': 'babel-mailbox-v1', 'command': command})
            row = stream.receive()
            # Never respond to ACP/reverse requests or accept logs as receipts.
            require(row.get('type') == 'control_result' and row.get('request_id') == 'babel-mailbox-v1')
            result = row.get('result')
            require(isinstance(result, dict) and set(result) == {'Ok'} and isinstance(result['Ok'], dict))
            return result['Ok']
        finally:
            stream.close()

    def sessions(self):
        result = self.control({'type': 'mailbox_sessions'})
        require(set(result) == {'type', 'sessions'} and result['type'] == 'mailbox_sessions')
        rows = result['sessions']
        require(isinstance(rows, list) and len(rows) <= 1024)
        data = {}
        for row in rows:
            require(isinstance(row, dict) and set(row) == {'id', 'cwd'})
            sid, cwd = row['id'], row['cwd']
            require(isinstance(sid, str) and UUID.fullmatch(sid) and sid == sid.lower() and sid not in data and
                    isinstance(cwd, str) and len(cwd) <= 4096 and Path(cwd).is_absolute())
            data[sid] = {'id': sid, 'cwd': cwd, 'status': 'idle'}
        return data

    def loaded(self):
        return list(self.sessions())

    def metadata(self, sid):
        require(isinstance(sid, str) and UUID.fullmatch(sid))
        row = self.sessions().get(sid)
        if row is None:
            raise NativeRejected('Grok session unavailable or busy')
        return row

    def queue(self, sid, cwd, notice, expires):
        if self.metadata(sid)['cwd'] != cwd:
            raise NativeRejected('Grok native workspace changed')
        require(time.time() + 12 < expires)
        # Stable per native session/notice. The bridge ledger pins intent before
        # this boundary, and the native runtime deduplicates repeat control IDs.
        nid = hashlib.sha256((sid + '\0' + notice).encode()).hexdigest()
        result = self.control({'type': 'queue_mailbox_notification', 'session_id': sid,
                               'notification_id': nid, 'text': notice})
        require(set(result) == {'type', 'session_id', 'notification_id', 'state'} and
                result['type'] == 'mailbox_notification' and result['session_id'] == sid and result['notification_id'] == nid)
        if result['state'] in ('busy', 'not_live', 'capacity'):
            raise NativeRejected('Grok native notification rejected')
        require(result['state'] in ('queued', 'duplicate'))
