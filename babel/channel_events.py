"""Opt-in ID-only approval stream. Commit signals, never periodic inbox polling.

The SQLite approval audit is the durable source. A private Unix datagram is only
a cross-process wake hint; it cannot supply messages or authenticate a recipient.
"""
from contextlib import contextmanager
import json
import hashlib
import os
from pathlib import Path
import select
import socket
import stat
import threading
import time
from .core import BridgeError
from .events import EVENT_NAME, canonical, iso

STREAM_HEADER = "Babel-Event-Stream"
STREAM_VERSION = "approved-v1"
MAX_STREAMS = 8
MAX_EVENTS = 10000  # Same bound as durable message storage; no unbounded dedupe.
STREAM_SECONDS = 300
HEARTBEAT_SECONDS = 15
EVENT_INTERVAL = 1  # At most 60 metadata notifications/minute per stream.


def cursor(value):
    import re
    if value is None:
        return 0
    if not isinstance(value, str) or not re.fullmatch(r"approved_[1-9][0-9]{0,18}", value):
        raise BridgeError("Invalid approval stream cursor")
    number = int(value[9:])
    if number > 2 ** 63 - 1:
        raise BridgeError("Invalid approval stream cursor")
    return number


def socket_path(database):
    return str(Path(database).absolute()) + ".approvals.sock"


def notify_gateway(database):
    path = socket_path(database)
    try:
        info = os.lstat(path)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            return
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            sock.sendto(b"1", path)
    except OSError:
        # Missing listener: reconnect replays queued rows. A full receive buffer
        # already contains a wake hint. Failed sends never roll back an approval.
        pass


class ApprovalSource:
    def __init__(self, store, recipients):
        self.store = store
        self.recipients = frozenset(recipients)
        self.lock = threading.Lock()
        self.active = set()
        self.closed = False
        self.sock = self.lock_fd = self.thread = None
        self.bound = False
        if str(store.path) != ":memory:":
            try:
                import fcntl
            except ImportError:
                raise BridgeError("Approval stream requires Unix socket and lock support") from None
            path = socket_path(store.path)
            parent = Path(path).parent
            info = parent.stat()
            if parent.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise BridgeError("Approval signal requires a private database directory")
            try:
                self.lock_fd = os.open(path + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                info = os.fstat(self.lock_fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_mode & 0o077 or info.st_nlink != 1):
                    raise BridgeError("Approval signal lock must be private")
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if os.path.lexists(path):
                    info = os.lstat(path)
                    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                        raise BridgeError("Unsafe approval signal path")
                    os.unlink(path)
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                self.sock.bind(path)
                self.bound = True
                os.chmod(path, 0o600)
                self.stop_read, self.stop_write = socket.socketpair()
                self.thread = threading.Thread(target=self.listen, daemon=True)
                self.thread.start()
            except Exception:
                if self.sock:
                    self.sock.close()
                if self.bound:
                    os.unlink(path)
                if self.lock_fd is not None:
                    os.close(self.lock_fd)
                raise BridgeError("Approval signal listener unavailable") from None

    def listen(self):
        while not self.closed:
            ready, _, _ = select.select([self.sock, self.stop_read], [], [])
            if self.stop_read in ready:
                return
            if self.sock in ready:
                self.sock.recv(16)
                with self.store.approval_condition:
                    self.store.approval_generation += 1
                    self.store.approval_condition.notify_all()

    def close(self):
        if self.closed:
            return
        self.closed = True
        with self.store.approval_condition:
            self.store.approval_condition.notify_all()
        if self.thread:
            self.stop_write.send(b"1")
            self.thread.join(timeout=2)
            self.sock.close()
            os.unlink(socket_path(self.store.path))
            self.stop_read.close()
            self.stop_write.close()
            os.close(self.lock_fd)

    @contextmanager
    def reserve(self, role):
        with self.lock:
            if role not in self.recipients:
                raise BridgeError("Approval stream is not enabled for this recipient", 403)
            if self.closed or len(self.active) >= MAX_STREAMS or role in self.active:
                raise BridgeError("Approval stream capacity reached", 429)
            self.active.add(role)
        try:
            yield
        finally:
            with self.lock:
                self.active.discard(role)

    def pending(self, policy, role, after=0):
        policy.assert_active(role)
        # Select metadata only, never text, receipt or credentials. Audit sequence
        # orders approvals (a later-created draft may be approved first).
        with self.store.lock:
            rows = self.store.db.execute("""SELECT e.seq AS event_seq, m.id, m.source,
                m.recipient, m.root_id, m.hops, m.conversation_id, m.source_owner,
                m.recipient_owner, m.approved FROM events e JOIN messages m ON m.id=e.message_id
                WHERE e.action='approved' AND m.recipient=? AND m.status='queued' AND e.seq>?
                ORDER BY e.seq LIMIT ?""", (role, after, MAX_EVENTS)).fetchall()
        result = []
        for row in rows:
            row = dict(row)
            try:
                policy.check_row(row)
            except BridgeError:
                continue
            if not 1 <= row["hops"] <= policy.hop_limit(row["conversation_id"]):
                continue
            # Same envelope, stable event ID and payload as Store._queue_wakes.
            # Only SSE framing adds an audit cursor; webhook ledger is untouched.
            result.append({"transport_cursor": "approved_" + str(row["event_seq"]),
                "packet": {"eventId": "evt_" + hashlib.sha256(row["id"].encode("ascii")).hexdigest(),
                    "name": EVENT_NAME, "timestamp": iso(row["approved"]),
                    "data": {"message_id": row["id"], "recipient": role,
                             "root_id": row["root_id"], "hops": row["hops"]}, "cursor": None}})
        return result

    def serve(self, handler, role, fingerprint, after=0):
        with self.reserve(role):
            handler.approval_stream_started = True
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream")
            handler.send_header("Cache-Control", "no-store")
            handler.send_header("X-Content-Type-Options", "nosniff")
            handler.send_header("Connection", "close")
            handler.send_header("X-Accel-Buffering", "no")
            handler.end_headers()
            handler.close_connection = True
            handler.wfile.write(b": connected\n\n")
            handler.wfile.flush()
            seen = set()
            deadline = time.monotonic() + STREAM_SECONDS
            generation = -1
            next_emit = 0
            while not self.closed and time.monotonic() < deadline:
                # Heartbeats check authorization and socket liveness, not inboxes.
                policy = handler.server.current_policy()
                policy.assert_active(role)
                if policy.agents[role][0] != fingerprint or role not in self.recipients:
                    return
                with self.store.approval_condition:
                    current = self.store.approval_generation
                if current != generation:
                    # Capture generation BEFORE query so a concurrent commit
                    # causes another scan rather than a lost wake.
                    generation = current
                    for event in self.pending(policy, role, after):
                        packet = event["packet"]
                        if packet["eventId"] in seen:
                            continue
                        # Rate pacing a known event is not a scheduled inbox
                        # check. Reauthorize and recheck queued state after wait.
                        with self.store.approval_condition:
                            while next_emit > time.monotonic() and not self.closed:
                                self.store.approval_condition.wait(timeout=next_emit - time.monotonic())
                        if self.closed or time.monotonic() >= deadline:
                            return
                        policy = handler.server.current_policy()
                        policy.assert_active(role)
                        if policy.agents[role][0] != fingerprint:
                            return
                        if not self.available(policy, role, packet["data"]["message_id"]):
                            continue
                        seen.add(packet["eventId"])
                        data = canonical(packet).encode()
                        handler.wfile.write(b"id: " + event["transport_cursor"].encode() + b"\n"
                                            b"event: " + EVENT_NAME.encode() + b"\ndata: " + data + b"\n\n")
                        handler.wfile.flush()
                        after = cursor(event["transport_cursor"])
                        next_emit = time.monotonic() + EVENT_INTERVAL
                with self.store.approval_condition:
                    if self.store.approval_generation == generation and not self.closed:
                        self.store.approval_condition.wait(timeout=min(HEARTBEAT_SECONDS,
                            max(0, deadline - time.monotonic())))
                handler.wfile.write(b": keepalive\n\n")
                handler.wfile.flush()

    def available(self, policy, role, message_id):
        with self.store.lock:
            row = self.store.db.execute("""SELECT status, source, recipient,
                conversation_id, source_owner, recipient_owner, hops FROM messages WHERE id=?""",
                (message_id,)).fetchone()
        if not row or row["status"] != "queued" or row["recipient"] != role:
            return False
        try:
            policy.check_row(dict(row))
            return 1 <= row["hops"] <= policy.hop_limit(row["conversation_id"])
        except BridgeError:
            return False
