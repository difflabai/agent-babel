"""Bounded, same-UID Codex control-socket client. No native start or resume.

Only initialize, loaded-thread discovery, metadata reads and `codex queue` are
used. This deliberately does not subscribe to transcripts or model output.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import time

from account_session_helper import private
from babel.account_bootstrap import UUID

LIMIT = 1048576


class NativeUnavailable(RuntimeError):
    pass


class NativeRejected(NativeUnavailable):
    """Explicit native rejection before any notification was admitted."""


def require(condition):
    if not condition:
        raise NativeUnavailable('Native receiver unavailable')


class UnixWebSocket:
    """RFC6455 client for the local control socket; no TCP, redirects or TLS."""
    def __init__(self, path, expected=None):
        private(path.parent, True)
        link = path.lstat()
        require(link.st_uid == os.getuid())
        target = path
        if stat.S_ISLNK(link.st_mode):
            target = Path(os.readlink(path))
            require(target.is_absolute() and target.parent == Path('/tmp') / ('codex-daemon-' + str(os.getuid()))
                    and re.fullmatch(r'[a-f0-9]{64}', target.name))
        require(not any(p.is_symlink() for p in (target, *target.parents)))
        private(target.parent, True)
        info = target.stat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077)
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.deadline = time.monotonic() + 5
        self.budget()
        self.buffer = bytearray()
        try:
            self.socket.connect(str(target))
            pid, uid, _ = struct.unpack('3i', self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == os.getuid())
            binary = Path('/proc', str(pid), 'exe').resolve(strict=True)
            require(not any(p.is_symlink() for p in (binary, *binary.parents)))
            executable = binary.stat()
            require(stat.S_ISREG(executable.st_mode) and executable.st_uid in (0, uid)
                    and not executable.st_mode & 0o022)
            start = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]
            self.identity = {'pid': pid, 'start': start, 'uid': uid, 'binary': str(binary),
                             'binary_inode': executable.st_ino, 'binary_device': executable.st_dev,
                             'binary_mtime': executable.st_mtime_ns,
                             'socket_inode': info.st_ino, 'socket_device': info.st_dev,
                             'target': str(target),
                             'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
            require(expected is None or expected == self.identity)
            key = base64.b64encode(secrets.token_bytes(16)).decode('ascii')
            request = ('GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n'
                       'Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ' + key + '\r\n\r\n')
            self.budget()
            self.socket.sendall(request.encode('ascii'))
            while b'\r\n\r\n' not in self.buffer:
                require(len(self.buffer) < 16384)
                self.budget()
                chunk = self.socket.recv(4096)
                require(bool(chunk))
                self.buffer.extend(chunk)
            header, remaining = self.buffer.split(b'\r\n\r\n', 1)
            require(len(header) <= 16384)
            self.buffer = bytearray(remaining)
            lines = header.decode('ascii').split('\r\n')
            require(lines[0].split(' ', 2)[:2] == ['HTTP/1.1', '101'])
            headers = {}
            for line in lines[1:]:
                name, value = line.split(':', 1)
                require(name.lower() not in headers)
                headers[name.lower()] = value.strip()
            accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            require(headers.get('sec-websocket-accept') == accept and
                    headers.get('upgrade', '').lower() == 'websocket' and
                    'upgrade' in [v.strip() for v in headers.get('connection', '').lower().split(',')] and
                    'sec-websocket-extensions' not in headers)
        except BaseException:
            self.socket.close()
            raise

    def close(self):
        self.socket.close()

    def budget(self):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0)
        self.socket.settimeout(remaining)

    def read(self, count):
        while len(self.buffer) < count:
            self.budget()
            chunk = self.socket.recv(min(65536, count - len(self.buffer)))
            require(bool(chunk))
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def send(self, payload, opcode=1):
        require(len(payload) <= LIMIT)
        length = len(payload)
        header = bytes([0x80 | opcode, 0x80 | (length if length < 126 else 126 if length < 65536 else 127)])
        if length >= 126:
            header += struct.pack('!H' if length < 65536 else '!Q', length)
        mask = secrets.token_bytes(4)
        self.budget()
        self.socket.sendall(header + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(payload)))

    def receive(self):
        message = bytearray()
        started = False
        for _ in range(128):
            first, second = self.read(2)
            require(not first & 0x70 and not second & 0x80)
            final, opcode, length = bool(first & 0x80), first & 15, second & 127
            if length == 126:
                length = struct.unpack('!H', self.read(2))[0]
            elif length == 127:
                length = struct.unpack('!Q', self.read(8))[0]
            require(length <= LIMIT and len(message) + length <= LIMIT)
            if opcode >= 8:
                require(final and length <= 125 and opcode in (8, 9, 10))
                payload = self.read(length)
                if opcode == 8:
                    raise NativeUnavailable('Native socket closed')
                if opcode == 9:
                    self.send(payload, opcode=10)
                continue
            require(opcode == (0 if started else 1))
            started = True
            message.extend(self.read(length))
            if final:
                value = json.loads(message.decode('utf-8'))
                require(isinstance(value, dict))
                return value
        raise NativeUnavailable('Native frame capacity reached')


class Native:
    def __init__(self, path, identity=None):
        self.path, self.identity = Path(path), identity

    def rpc(self, method, params):
        ws = UnixWebSocket(self.path, self.identity)
        try:
            self.identity = ws.identity
            def call(mid, name, args):
                ws.deadline = time.monotonic() + 5
                ws.send(json.dumps({'id': mid, 'method': name, 'params': args}).encode())
                for _ in range(32):
                    ws.budget()
                    row = ws.receive()
                    if row.get('id') == mid and 'method' not in row:
                        require('error' not in row and 'result' in row)
                        return row['result']
                    require('id' not in row)  # Never answer unrelated server requests.
                raise NativeUnavailable('Native RPC response unavailable')
            call(1, 'initialize', {'clientInfo': {'name': 'babel_account_receiver', 'version': '1.0.0'},
                                   'capabilities': {'experimentalApi': False}})
            ws.deadline = time.monotonic() + 5
            ws.send(b'{"method":"initialized","params":{}}')
            return call(2, method, params)
        finally:
            ws.close()

    def loaded(self):
        rows = self.rpc('thread/loaded/list', {})['data']
        require(isinstance(rows, list) and len(rows) <= 1024 and
                all(isinstance(row, str) and UUID.fullmatch(row) for row in rows))
        require(len(set(rows)) == len(rows))
        return rows

    def metadata(self, sid):
        require(isinstance(sid, str) and UUID.fullmatch(sid))
        row = self.rpc('thread/read', {'threadId': sid, 'includeTurns': False})['thread']
        require(row.get('id') == sid and isinstance(row.get('cwd'), str))
        require(row.get('status', {}).get('type') in ('active', 'idle'))
        return {'id': sid, 'cwd': row['cwd'], 'status': row['status']['type']}

    def queue(self, sid, cwd, notice, expires):
        require(self.metadata(sid)['cwd'] == cwd)
        require(time.time() + 12 < expires)
        env = os.environ.copy()
        env.pop('CODEX_THREAD_ID', None)
        env.pop('BABEL_SESSION_TOKEN', None)
        result = subprocess.run([self.identity['binary'], 'queue', '--remote',
                                 'unix://' + self.identity['target'], '--thread', sid, '--message', notice],
                                cwd=cwd, env=env, capture_output=True, timeout=10)
        require(result.returncode == 0)
