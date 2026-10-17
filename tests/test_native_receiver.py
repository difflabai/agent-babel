"""Native wire checks use private local sockets and synthetic JSON, never a model."""
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from babel import native_receiver as native
from tests.account_client_fixture import SID


def exact(stream, count):
    result = bytearray()
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise EOFError('Synthetic client disconnected')
        result.extend(chunk)
    return bytes(result)


def read_frame(stream):
    first, second = exact(stream, 2)
    if first != 0x81 or not second & 0x80:
        raise AssertionError('Client must send a masked final text frame')
    length = second & 127
    if length >= 126:
        length = struct.unpack('!H' if length == 126 else '!Q', exact(stream, 2 if length == 126 else 8))[0]
    mask = exact(stream, 4)
    payload = exact(stream, length)
    return json.loads(bytes(value ^ mask[i % 4] for i, value in enumerate(payload)))


def send_frame(stream, value):
    raw = json.dumps(value).encode()
    size = len(raw)
    header = bytes([0x81, size if size < 126 else 126])
    if size >= 126:
        header += struct.pack('!H', size)
    stream.sendall(header + raw)


class NativeWireTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'native.sock'
        # The synthetic peer is this test interpreter, which some Conda installs
        # make group-writable. Model its binary as an approved private executable;
        # retain real SO_PEERCRED, PID/start, socket inode and all socket I/O.
        binary = Path('/proc/self/exe').resolve()
        original = Path.stat
        self.binary_write_bits = 0

        def runtime_stat(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == binary:
                return SimpleNamespace(st_mode=(info.st_mode & ~0o022) | self.binary_write_bits,
                                       st_uid=info.st_uid, st_ino=info.st_ino,
                                       st_dev=info.st_dev, st_mtime_ns=info.st_mtime_ns)
            return info

        metadata = patch.object(native.Path, 'stat', runtime_stat)
        metadata.start()
        self.addCleanup(metadata.stop)

    @contextlib.contextmanager
    def peer(self, *, connections=1, expect_upgrade=True):
        requests, errors = [], []
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path))
        self.path.chmod(0o600)
        listener.listen(2)
        listener.settimeout(3)

        def serve():
            try:
                for _ in range(connections):
                    stream, _ = listener.accept()
                    with stream:
                        stream.settimeout(3)
                        header = bytearray()
                        while b'\r\n\r\n' not in header:
                            chunk = stream.recv(4096)
                            if not chunk:
                                if expect_upgrade:
                                    raise EOFError('Expected synthetic WebSocket upgrade')
                                break
                            header.extend(chunk)
                        if not expect_upgrade:
                            self.assertEqual(header, b'')
                            continue
                        headers = dict(line.split(':', 1) for line in header.decode().split('\r\n')[1:] if ':' in line)
                        key = headers['Sec-WebSocket-Key'].strip()
                        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                        stream.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                                        'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n').encode())
                        initialize = read_frame(stream)
                        requests.append(initialize)
                        self.assertEqual(initialize['method'], 'initialize')
                        send_frame(stream, {'id': initialize['id'], 'result': {}})
                        initialized = read_frame(stream)
                        self.assertEqual(initialized['method'], 'initialized')
                        request = read_frame(stream)
                        requests.append(request)
                        result = {'data': [SID]} if request['method'] == 'thread/loaded/list' else {
                            'thread': {'id': SID, 'cwd': '/synthetic/task', 'status': {'type': 'idle'}, 'turns': []}}
                        send_frame(stream, {'id': request['id'], 'result': result})
            except BaseException as error:
                errors.append(error)
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield requests
        finally:
            thread.join(timeout=4)
            listener.close()
            self.assertFalse(thread.is_alive(), 'Synthetic native peer did not terminate')
            if errors:
                raise errors[0]

    def test_real_unix_websocket_discovers_and_reads_without_subscribing(self):
        with self.peer(connections=2) as requests:
            instance = native.Native(self.path)
            self.assertEqual(instance.loaded(), [SID])
            self.assertEqual(instance.metadata(SID), {'id': SID, 'cwd': '/synthetic/task', 'status': 'idle'})
        self.assertEqual([item['method'] for item in requests],
                         ['initialize', 'thread/loaded/list', 'initialize', 'thread/read'])
        self.assertEqual(requests[-1]['params'], {'threadId': SID, 'includeTurns': False})
        self.assertEqual(instance.identity['uid'], os.getuid())

    def test_wrong_unix_peer_is_rejected_before_upgrade(self):
        with self.peer(expect_upgrade=False), \
                patch.object(native.struct, 'unpack', return_value=(os.getpid(), os.getuid() + 1, os.getgid())):
            with self.assertRaises(native.NativeUnavailable):
                native.Native(self.path).loaded()

    def test_replaced_socket_cannot_reuse_authenticated_runtime(self):
        with self.peer():
            instance = native.Native(self.path)
            self.assertEqual(instance.loaded(), [SID])
        self.path.rename(self.path.with_name('old.sock'))
        with self.peer(expect_upgrade=False):
            with self.assertRaises(native.NativeUnavailable):
                instance.loaded()

    def test_writable_native_executable_is_rejected_before_upgrade(self):
        self.binary_write_bits = 0o020
        with self.peer(expect_upgrade=False):
            with self.assertRaises(native.NativeUnavailable):
                native.Native(self.path).loaded()

    def test_upgrade_trickle_cannot_extend_absolute_deadline(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.path))
            self.path.chmod(0o600)
            clock = [0]

            class TrickleSocket:
                reads, closed = 0, False

                def connect(self, path):
                    pass

                def getsockopt(self, *args):
                    return struct.pack('3i', os.getpid(), os.getuid(), os.getgid())

                def settimeout(self, seconds):
                    if seconds <= 0:
                        raise AssertionError('Invalid socket timeout')

                def sendall(self, raw):
                    pass

                def recv(self, count):
                    clock[0] += 2
                    self.reads += 1
                    return b'H'

                def close(self):
                    self.closed = True

            stream = TrickleSocket()
            with patch.object(native.socket, 'socket', return_value=stream), \
                    patch.object(native.time, 'monotonic', side_effect=lambda: clock[0]):
                with self.assertRaises(native.NativeUnavailable):
                    native.UnixWebSocket(self.path)
            self.assertEqual(stream.reads, 3)
            self.assertTrue(stream.closed)


if __name__ == '__main__':
    unittest.main()
