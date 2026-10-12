"""Synthetic, off-production channel tests. No real credentials or native agents."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener
from babel.auth import Policy, ScopedStore
from babel.channel_events import ApprovalSource, cursor, STREAM_HEADER, STREAM_VERSION
from babel.events import EVENT_NAME, EventService, canonical
from babel.wake import WakeConfig
from tests.test_cloud import FakeTransport, KEY
from babel.claude_channel import BabelClient, Channel, ExistingMailbox, channel_notification, parse_events, stdio
from babel.core import BridgeError, Store
from babel.gateway import Gateway
from babel.mcp import dispatch

EMBER = "fixture.dots.ember_01"
ADA = "fixture.grokbot.ada_01"
CLAUDE = "fixture.claude.worker_01"
SECOND = "fixture.claude.worker_02"
TOKENS = {pid: "public-synthetic-credential-" + str(i).zfill(12)
          for i, pid in enumerate((EMBER, ADA, CLAUDE, SECOND))}


def config():
    participants = {}
    for pid, token in TOKENS.items():
        owner, client, session = pid.split(".")
        participants[pid] = {"owner": owner, "client": client, "session": session, "state": "active",
            "accepted": True, "activated_at": int(time.time()) - 60, "expires": None,
            "sha256": hashlib.sha256(token.encode()).hexdigest()}
    conversations = {}
    for worker in (CLAUDE, SECOND):
        for sister in (EMBER, ADA):
            cid = "report_" + worker.split(".")[-1] + "_" + sister.split(".")[-1]
            conversations[cid] = {"state": "active", "participants": [worker, sister], "approval": "automatic",
                "routes": [{"sender": worker, "recipient": sister}, {"sender": sister, "recipient": worker}]}
    return {"schema_version": 3, "owners": {"fixture": {"enabled": True}},
            "participants": participants, "conversations": conversations}


def conversation(worker=CLAUDE, sister=EMBER):
    return "report_" + worker.split(".")[-1] + "_" + sister.split(".")[-1]


def event(mid="synthetic-message-001", n=1, recipient=CLAUDE):
    return {"event_id": "evt_" + hashlib.sha256(mid.encode()).hexdigest(), "message_id": mid, "recipient": recipient,
            "root_id": mid, "hops": 1, "transport_cursor": "approved_" + str(n)}


def packet(ev=None):
    ev = ev or event()
    return {"eventId": ev["event_id"], "name": EVENT_NAME, "timestamp": "2026-10-07T12:00:00.000Z",
            "data": {key: ev[key] for key in ("message_id", "recipient", "root_id", "hops")}, "cursor": None}


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.policy = Policy(config())
        self.store.sync_policy(self.policy)
        self.store.policy_provider = lambda: self.policy
        self.source = ApprovalSource(self.store, [CLAUDE])
    def tearDown(self):
        self.source.close()
        self.store.close()
    def stage(self, mid="synthetic-message-001", worker=CLAUDE, sister=EMBER, policy=None):
        p = policy or self.policy
        return self.store.stage(sister, worker, "selected synthetic body never in wake", message_id=mid,
            conversation_id=conversation(worker, sister), policy=p)["message"]
    def test_committed_approvals_only_and_rollback_sends_no_hint(self):
        cfg = config()
        cfg["conversations"][conversation()]["approval"] = "manual"
        self.policy = Policy(cfg)
        self.stage()
        self.assertEqual(self.store.approval_generation, 0)
        self.assertEqual(self.source.pending(self.policy, CLAUDE), [])
        self.store.approve("synthetic-message-001")
        self.assertEqual(self.store.approval_generation, 1)
        self.store.approve("synthetic-message-001")
        self.assertEqual(self.store.approval_generation, 1)
        with self.assertRaises(ValueError):
            with self.store.transaction():
                self.store._event("synthetic-message-001", "approved", "synthetic-rollback")
                raise ValueError("rollback")
        self.assertEqual(self.store.approval_generation, 1)
        self.assertEqual(len(self.source.pending(self.policy, CLAUDE)), 1)
    def test_id_only_scoped_order_dedupe_cursor_and_receipt_separation(self):
        self.stage("synthetic-message-001")
        self.stage("synthetic-message-002", sister=ADA)
        self.stage("other-mailbox-message", worker=SECOND)
        pending = self.source.pending(self.policy, CLAUDE)
        self.assertEqual([p["packet"]["data"]["message_id"] for p in pending], ["synthetic-message-001", "synthetic-message-002"])
        self.assertEqual(set(pending[0]["packet"]["data"]), {"message_id", "recipient", "root_id", "hops"})
        self.assertNotIn("selected synthetic", json.dumps(pending))
        self.assertEqual(self.source.pending(self.policy, CLAUDE, cursor(pending[0]["transport_cursor"])), pending[1:])
        self.assertEqual(self.store._row(pending[0]["packet"]["data"]["message_id"])["status"], "queued")
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM message_claims").fetchone()[0], 0)
    def test_canceled_acknowledged_and_removed_route_are_not_replayed(self):
        self.stage("synthetic-message-001")
        self.stage("synthetic-message-002")
        self.store.cancel("synthetic-message-001")
        self.store.claim_message("synthetic-message-002", CLAUDE, "synthetic-claim-01")
        self.store.acknowledge_claim("synthetic-message-002", CLAUDE, "synthetic-claim-01")
        self.assertEqual(self.source.pending(self.policy, CLAUDE), [])
        self.stage("synthetic-message-003")
        cfg = config(); cfg["conversations"][conversation()]["routes"] = []
        self.assertEqual(self.source.pending(Policy(cfg), CLAUDE), [])
    def test_participant_owner_rotation_and_route_checks(self):
        self.stage()
        cfg = config(); cfg["owners"]["fixture"]["enabled"] = False
        with self.assertRaises(BridgeError): self.source.pending(Policy(cfg), CLAUDE)
        cfg = config(); cfg["participants"][CLAUDE]["state"] = "revoked"
        with self.assertRaises(BridgeError): self.source.pending(Policy(cfg), CLAUDE)
        cfg = config(); cfg["conversations"][conversation()]["max_hops"] = 1
        with self.store.transaction(): self.store.db.execute("UPDATE messages SET hops=2")
        self.assertEqual(self.source.pending(Policy(cfg), CLAUDE), [])
    def test_single_stream_exact_recipient_and_capacity(self):
        with self.assertRaises(BridgeError):
            with self.source.reserve(SECOND): pass
        with self.source.reserve(CLAUDE):
            with self.assertRaises(BridgeError) as exc:
                with self.source.reserve(CLAUDE): pass
            self.assertEqual(exc.exception.status, 429)
        with self.source.reserve(CLAUDE): pass
        self.source.close()
        with self.assertRaises(BridgeError):
            with self.source.reserve(CLAUDE): pass
    def test_approval_order_is_not_creation_order(self):
        cfg = config(); cfg["conversations"][conversation()]["approval"] = "manual"
        self.policy = Policy(cfg)
        self.stage("synthetic-message-001"); self.stage("synthetic-message-002")
        self.store.approve("synthetic-message-002"); self.store.approve("synthetic-message-001")
        self.assertEqual([e["packet"]["data"]["message_id"] for e in self.source.pending(self.policy, CLAUDE)],
                         ["synthetic-message-002", "synthetic-message-001"])
    def test_identical_existing_webhook_envelope_and_untouched_delivery_ledger(self):
        transport = FakeTransport()
        config = WakeConfig({"enabled": True, "callback_hosts": {CLAUDE: ["claude.fixture.example.com"]}})
        service = EventService(self.store, self.policy, config, transport)
        service.subscribe(CLAUDE, {"name": EVENT_NAME, "arguments": {"recipient": CLAUDE},
            "delivery": {"mode": "webhook", "url": "https://claude.fixture.example.com/event", "secret": KEY}})
        self.stage()
        outbox_before = dict(self.store.db.execute("SELECT * FROM outbox").fetchone())
        stream_packet = self.source.pending(self.policy, CLAUDE)[0]["packet"]
        self.assertEqual(canonical(stream_packet), outbox_before["body"])
        self.assertEqual(stream_packet["eventId"], outbox_before["event_id"])
        self.assertEqual(dict(self.store.db.execute("SELECT * FROM outbox").fetchone()), outbox_before)
        self.assertTrue(service.process_one())
        self.assertEqual(transport.calls[-1][2], canonical(stream_packet).encode())
        self.assertEqual(self.store._row("synthetic-message-001")["status"], "queued")
    def test_stream_push_on_commit_no_periodic_pending_checks(self):
        class Handler:
            def __init__(h):
                h.server = Mock(current_policy=lambda: self.policy)
                h.wfile = io.BytesIO(); h.headers = {}
            def send_response(h, value): self.assertEqual(value, 200)
            def send_header(h, *args): pass
            def end_headers(h): pass
        handler = Handler()
        calls = []
        pending = self.source.pending
        def counted(*args): calls.append(time.monotonic()); return pending(*args)
        self.source.pending = counted
        with patch("babel.channel_events.HEARTBEAT_SECONDS", 0.01), patch("babel.channel_events.STREAM_SECONDS", 0.3):
            thread = threading.Thread(target=self.source.serve, args=(handler, CLAUDE, self.policy.agents[CLAUDE][0]))
            thread.start()
            deadline = time.monotonic() + 1
            while not calls and time.monotonic() < deadline: time.sleep(0.001)
            time.sleep(0.03)
            self.assertEqual(len(calls), 1)  # Heartbeats do not scan the mailbox.
            self.stage()
            deadline = time.monotonic() + 1
            while b"data:" not in handler.wfile.getvalue() and time.monotonic() < deadline: time.sleep(0.001)
            self.source.close(); thread.join(timeout=1)
        output = handler.wfile.getvalue()
        self.assertIn(b"synthetic-message-001", output)
        self.assertNotIn(b"selected synthetic body", output)
        self.assertEqual(output.count(b"data:"), 1)
        self.assertEqual(self.store._row("synthetic-message-001")["status"], "queued")
    def test_race_commit_between_scan_and_wait_not_lost(self):
        # Snapshot capture precedes pending scan: even a commit immediately after
        # that scan changes generation, and the condition wait must be skipped.
        before = self.store.approval_generation
        self.assertEqual(self.source.pending(self.policy, CLAUDE), [])
        self.stage()
        with self.store.approval_condition:
            self.assertNotEqual(self.store.approval_generation, before)
        self.assertEqual(len(self.source.pending(self.policy, CLAUDE)), 1)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO(); self.logs = []
        self.client = Mock()
        self.channel = Channel(self.client, CLAUDE, self.output, self.logs.append)
    def tearDown(self): self.channel.close()
    def rpc(self, method, params=None, rid=1):
        request = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if rid is not None: request["id"] = rid
        return self.channel.handle(request)
    def test_legacy_capability_handshake_no_permission_relay_and_no_hot_start(self):
        result = self.rpc("initialize", {"protocolVersion": "2026-07-28"})["result"]
        self.assertEqual(result["protocolVersion"], "2025-11-25")
        self.assertEqual(result["capabilities"]["experimental"], {"claude/channel": {}})
        self.assertIsNone(self.channel.thread)
        thread = Mock()
        with patch("babel.claude_channel.threading.Thread", return_value=thread):
            self.rpc("notifications/initialized", rid=None)
            self.rpc("notifications/initialized", rid=None)
        thread.start.assert_called_once()
        self.assertIn("error", self.rpc("initialize"))
    def test_tool_catalog_and_only_existing_babel_tools(self):
        self.assertIn("error", self.rpc("tools/list"))
        self.rpc("initialize")
        catalog = self.rpc("tools/list")["result"]["tools"]
        self.assertEqual(len(catalog), 7)
        self.assertIn("conversation_id", catalog[0]["inputSchema"]["required"])
        for name in ("shell", "permission", "synthetic_transfer", "enroll"):
            self.assertIn("error", self.rpc("tools/call", {"name": name}))
        self.assertIn("error", self.rpc("tools/call", {"name": ["list_contacts"]}))
        self.client.rpc.assert_not_called()
        self.client.rpc.return_value = {"content": [], "isError": False}
        self.rpc("tools/call", {"name": "list_contacts", "arguments": {}})
        self.client.rpc.assert_called_once_with("tools/call", {"name": "list_contacts", "arguments": {}})
    def test_tool_failure_is_sanitized_and_never_auto_retried(self):
        self.rpc("initialize")
        self.client.rpc.side_effect = OSError("secret Authorization header must never echo")
        result = self.rpc("tools/call", {"name": "stage_message", "arguments": {}})
        self.assertTrue(result["result"]["isError"])
        self.assertNotIn("Authorization", json.dumps(result))
        self.client.rpc.assert_called_once()
    def test_notifications_id_only_validation_and_bad_payloads(self):
        notice = channel_notification(event(), CLAUDE)
        self.assertEqual(notice["method"], "notifications/claude/channel")
        self.assertTrue(all(isinstance(v, str) for v in notice["params"]["meta"].values()))
        for bad in (event(recipient=SECOND), {**event(), "text": "injected"},
                    {**event(), "hops": True}, {**event(), "hops": 101}, {**event(), "event_id": "fake_id"}):
            with self.assertRaises(BridgeError): channel_notification(bad, CLAUDE)
    def test_reconnect_dedupe_and_order_without_receipt_or_content_fetch(self):
        packets = [[event(n=1), event("synthetic-message-002", 2)],
                   [event("synthetic-message-002", 2), event("synthetic-message-003", 3)]]
        def events(stop):
            items = packets.pop(0)
            yield from items
            if not packets: stop.set()
        self.client.events.side_effect = events
        with patch.object(self.channel.stop, "wait", return_value=False): self.channel.pump()
        notices = [json.loads(line) for line in self.output.getvalue().splitlines()]
        self.assertEqual([n["params"]["meta"]["event_id"] for n in notices],
            [event()["event_id"], event("synthetic-message-002")["event_id"], event("synthetic-message-003")["event_id"]])
        self.client.rpc.assert_not_called()
    def test_invalid_binding_and_auth_gate_stop_without_retry(self):
        self.client.events.return_value = iter([event(recipient=SECOND)])
        self.channel.pump()
        self.assertEqual(self.output.getvalue(), "")
        self.assertIn("mismatched", self.logs[-1])
        self.client.events.side_effect = HTTPError("https://fixture", 403, "sensitive", {}, None)
        self.channel.pump()
        self.assertIn("gate", self.logs[-1]); self.assertNotIn("sensitive", str(self.logs))
    def test_unseen_out_of_order_event_stops_without_forwarding(self):
        self.client.events.return_value = iter([event(n=2), event("synthetic-message-002", 1)])
        self.channel.pump()
        self.assertEqual(len(self.output.getvalue().splitlines()), 1)
        self.assertIn("mismatched", self.logs[-1])
    def test_https_stream_cursor_advances_only_after_consumer_emits(self):
        class Response(io.BytesIO):
            def __init__(self, raw):
                super().__init__(raw)
                self.headers = Mock(get_content_type=lambda: "text/event-stream")
        raw = ("id: approved_1\nevent: " + EVENT_NAME + "\ndata: " + json.dumps(packet()) + "\n\n").encode()
        mailbox = Mock(headers=lambda: {"Authorization": "Bearer public-synthetic-credential-000000000001"})
        client = BabelClient(mailbox)
        client.opener = Mock()
        client.opener.open.return_value = Response(raw)
        stream = client.events(threading.Event())
        self.assertEqual(next(stream), event())
        self.assertIsNone(client.cursor)
        with self.assertRaises(StopIteration): next(stream)
        self.assertEqual(client.cursor, "approved_1")
        client.opener.open.return_value = Response(b": keepalive\n\n")
        self.assertEqual(list(client.events(threading.Event())), [])
        request = client.opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Last-event-id"), "approved_1")
        self.assertEqual(request.full_url, "https://babel.255bits.com/mcp/v1")
    def test_reconnect_attempt_bound_and_no_message_fetch_poll(self):
        self.client.events.side_effect = OSError("synthetic disconnection")
        with patch.object(self.channel.stop, "wait", return_value=False): self.channel.pump()
        self.assertEqual(self.client.events.call_count, 8)
        self.client.rpc.assert_not_called()
        self.assertIn("reconnect bound", self.logs[-1])
    def test_sse_parser_and_oversized_incomplete_or_foreign_frames(self):
        raw = ("id: approved_1\nevent: " + EVENT_NAME + "\ndata: " + json.dumps(packet()) + "\n\n").encode()
        self.assertEqual(list(parse_events(io.BytesIO(b": keepalive\n\n" + raw), threading.Event())), [event()])
        for bad in (raw[:-1], b"data: " + b"x" * 8193 + b"\n\n", raw.replace(b"approved_1\nevent", b"approved_0\nevent")):
            with self.assertRaises(BridgeError): list(parse_events(io.BytesIO(bad), threading.Event()))
    def test_claim_ack_reply_roundtrip_through_adapter_tools(self):
        store = Store(":memory:"); policy = Policy(config()); store.sync_policy(policy)
        scoped = ScopedStore(store, CLAUDE, policy.agents[CLAUDE][1], policy)
        self.client.rpc.side_effect = lambda method, params: dispatch(scoped, CLAUDE,
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})["result"]
        self.rpc("initialize")
        def tool(name, arguments):
            result = self.rpc("tools/call", {"name": name, "arguments": arguments})["result"]
            self.assertFalse(result["isError"])
            return json.loads(result["content"][0]["text"])
        for sister in (EMBER, ADA):
            with self.subTest(sister=sister):
                suffix = sister.split(".")[-1]
                row = store.stage(sister, CLAUDE, "bounded synthetic test", message_id="synthetic-message-"+suffix,
                                  conversation_id=conversation(CLAUDE, sister), policy=policy)["message"]
                args = {"message_id": row["id"], "claim_id": "synthetic-claim-"+suffix}
                self.assertTrue(tool("claim_message", args)["claimed"])
                tool("acknowledge_message", args)
                self.assertFalse(tool("claim_message", args)["claimed"])
                reply = {"message_id": "synthetic-reply-"+suffix, "recipient": sister,
                         "conversation_id": conversation(CLAUDE, sister), "reply_to": row["id"], "text": "verified synthetic reply"}
                sent = tool("stage_message", reply)
                self.assertEqual(sent["message"]["status"], "queued")
                self.assertTrue(tool("stage_message", reply)["duplicate"])
                result = self.rpc("tools/call", {"name": "stage_message", "arguments": {**reply, "source": SECOND}})
                self.assertTrue(result["result"]["isError"])
        store.close()
    def test_stdio_bound_and_no_non_json_stdout(self):
        raw = b"x" * 70000 + b"\n" + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "initialize"}).encode() + b"\n"
        stdio(self.channel, io.BytesIO(raw))
        results = [json.loads(line) for line in self.output.getvalue().splitlines()]
        self.assertEqual(results[0]["error"]["code"], -32700)
        self.assertEqual(results[1]["id"], 2)


class CredentialTests(unittest.TestCase):
    def test_read_only_existing_own_binding_no_files_created_or_credentials_echoed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); path = root / "claude-existing"; path.mkdir(mode=0o700)
            token = TOKENS[CLAUDE]
            (path / "token").write_text(token + "\n"); os.chmod(path / "token", 0o600)
            request = {"client": "claude", "participant": CLAUDE, "sha256": hashlib.sha256(token.encode()).hexdigest()}
            (path / "enrollment.json").write_text(json.dumps(request)); os.chmod(path / "enrollment.json", 0o600)
            before = {p.name: p.read_bytes() for p in path.iterdir()}
            mailbox = ExistingMailbox("existing", CLAUDE, root)
            self.assertEqual(mailbox.participant, CLAUDE)
            self.assertEqual(before, {p.name: p.read_bytes() for p in path.iterdir()})
            with self.assertRaises(BridgeError): ExistingMailbox("existing", SECOND, root)
            with self.assertRaises(FileNotFoundError): ExistingMailbox("missing", CLAUDE, root)
            self.assertFalse((root / "claude-missing").exists())
            os.chmod(path / "token", 0o644)
            with self.assertRaises(BridgeError): ExistingMailbox("existing", CLAUDE, root)
            (path / "token").unlink(); (path / "token").symlink_to(path / "enrollment.json")
            with self.assertRaises(OSError): ExistingMailbox("existing", CLAUDE, root)
            (path / "token").unlink(); os.mkfifo(path / "token", mode=0o600)
            with self.assertRaises(BridgeError): ExistingMailbox("existing", CLAUDE, root)
    def test_cursor_validation(self):
        self.assertEqual(cursor(None), 0); self.assertEqual(cursor("approved_10"), 10)
        for value in ("0", "approved_0", "approved_-1", "approved_1\n", "approved_" + "9" * 20):
            with self.assertRaises(BridgeError): cursor(value)
        with self.assertRaises(BridgeError): cursor("approved_9223372036854775808")


class ActivationConfigTests(unittest.TestCase):
    def test_explicit_claude_only_scope_validated_before_listener_or_store(self):
        policy = Policy(config())
        for recipients in ([EMBER], [CLAUDE, CLAUDE], {CLAUDE}, [True], [CLAUDE] * 9):
            with patch("babel.gateway.BoundedServer.__init__") as listen, patch("babel.gateway.Store") as storage:
                with self.assertRaises(BridgeError):
                    Gateway(0, policy, "https://fixture.example.com", channel_recipients=recipients)
                listen.assert_not_called(); storage.assert_not_called()
    def test_default_does_not_install_a_signal_listener_or_stream(self):
        store = Store(":memory:")
        def fake_listen(server, *args): server.server_address = ("127.0.0.1", 12345)
        try:
            with patch("babel.gateway.BoundedServer.__init__", fake_listen), patch("babel.gateway.ApprovalSource") as source:
                server = Gateway(0, Policy(config()), "https://fixture.example.com", store)
                self.assertIsNone(server.approvals); source.assert_not_called()
        finally: store.close()


class SocketTests(unittest.TestCase):
    def setUp(self):
        try:
            a, b = socket.socketpair(); a.close(); b.close()
            with socket.socket() as sock: sock.bind(("127.0.0.1", 0))
        except PermissionError:
            if os.environ.get("BABEL_REQUIRE_CHANNEL_SOCKETS") == "1":
                raise
            self.skipTest("Execution sandbox forbids local socket operations; run socket suite before activation")
    def test_cross_store_commit_signal_replay_and_private_single_listener(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bridge.sqlite3"
            store = Store(path); writer = Store(path); policy = Policy(config())
            store.sync_policy(policy); writer.sync_policy(policy)
            source = ApprovalSource(store, [CLAUDE])
            try:
                with self.assertRaises(BridgeError): ApprovalSource(store, [CLAUDE])
                before = store.approval_generation
                script = """import sys
from babel.core import Store
from babel.auth import Policy
from tests.test_claude_channel import config, conversation, EMBER, CLAUDE
store=Store(sys.argv[1]); policy=Policy(config()); store.sync_policy(policy)
store.stage(EMBER, CLAUDE, 'private synthetic text', message_id='synthetic-message-001',
            conversation_id=conversation(), policy=policy)
store.close()
"""
                subprocess.run([sys.executable, "-c", script, str(path)], check=True, capture_output=True, timeout=5)
                deadline = time.monotonic() + 2
                with store.approval_condition:
                    while store.approval_generation == before and time.monotonic() < deadline:
                        store.approval_condition.wait(timeout=deadline-time.monotonic())
                self.assertGreater(store.approval_generation, before)
                self.assertEqual(len(source.pending(policy, CLAUDE)), 1)
                self.assertEqual(os.stat(str(path) + ".approvals.sock").st_mode & 0o777, 0o600)
                source.close()
                # Lost/disconnected hint recovers from existing committed audit.
                writer.stage(ADA, CLAUDE, "second synthetic text", message_id="synthetic-message-002",
                             conversation_id=conversation(CLAUDE, ADA), policy=policy)
                source = ApprovalSource(store, [CLAUDE])
                self.assertEqual(len(source.pending(policy, CLAUDE)), 2)
            finally: source.close(); writer.close(); store.close()
    def test_http_opt_in_auth_role_protocol_and_default_unchanged(self):
        store = Store(":memory:"); policy = Policy(config())
        gateway = Gateway(0, policy, "https://fixture.example.com", store, channel_recipients=[CLAUDE])
        thread = threading.Thread(target=gateway.serve_forever, daemon=True); thread.start()
        opener = build_opener(ProxyHandler({}))
        base = "http://127.0.0.1:" + str(gateway.port)
        def get(role=CLAUDE, changes=None):
            headers = {"Host": "fixture.example.com", "X-Forwarded-Proto": "https", "Authorization": "Bearer " + TOKENS[role],
                       "Accept": "text/event-stream", "MCP-Protocol-Version": "2025-11-25", STREAM_HEADER: STREAM_VERSION}
            headers.update(changes or {})
            return opener.open(Request(base + "/mcp/v1", headers=headers), timeout=2)
        try:
            for role, changes, status in ((SECOND, {}, 403), (CLAUDE, {"Authorization": ""}, 401),
                    (CLAUDE, {"MCP-Protocol-Version": "2026-07-28"}, 400),
                    (CLAUDE, {STREAM_HEADER: ""}, 405), (CLAUDE, {"Origin": "https://evil.example.com"}, 403)):
                with self.assertRaises(HTTPError) as exc: get(role, changes)
                self.assertEqual(exc.exception.code, status)
            with get() as response:
                self.assertEqual(response.headers.get_content_type(), "text/event-stream")
                self.assertEqual(response.readline(), b": connected\n")
                response.readline()
                store.stage(EMBER, CLAUDE, "synthetic HTTP test", message_id="synthetic-message-001",
                            conversation_id=conversation(), policy=policy)
                frame = []
                while True:
                    line = response.readline()
                    frame.append(line)
                    if line == b"\n" and any(b"data:" in item for item in frame): break
                self.assertIn(b"synthetic-message-001", b"".join(frame))
                self.assertNotIn(b"synthetic HTTP test", b"".join(frame))
                self.assertEqual(store._row("synthetic-message-001")["status"], "queued")
        finally:
            gateway.shutdown(); gateway.server_close(); thread.join(); store.close()
    def test_http_reconnect_cursor_rotation_route_revocation_and_recipient_receipt(self):
        with tempfile.TemporaryDirectory() as tmp, patch("babel.channel_events.HEARTBEAT_SECONDS", 0.01), patch("babel.channel_events.EVENT_INTERVAL", 0.01):
            policy_path = Path(tmp) / "policy.json"
            cfg = config(); policy_path.write_text(json.dumps(cfg))
            policy = Policy.load(policy_path); store = Store(":memory:")
            gateway = Gateway(0, policy, "https://fixture.example.com", store, channel_recipients=[CLAUDE])
            thread = threading.Thread(target=gateway.serve_forever, daemon=True); thread.start()
            opener = build_opener(ProxyHandler({})); base = "http://127.0.0.1:" + str(gateway.port)
            def get(token=TOKENS[CLAUDE], last=None):
                headers = {"Host": "fixture.example.com", "X-Forwarded-Proto": "https", "Authorization": "Bearer " + token,
                    "Accept": "text/event-stream", "MCP-Protocol-Version": "2025-11-25", STREAM_HEADER: STREAM_VERSION}
                if last: headers["Last-Event-ID"] = last
                return opener.open(Request(base + "/mcp/v1", headers=headers), timeout=2)
            def read_event(response):
                frame = []
                while True:
                    line = response.readline()
                    if not line: raise AssertionError("Stream closed before synthetic event")
                    frame.append(line)
                    if line == b"\n":
                        if any(item.startswith(b"data:") for item in frame):
                            return next(parse_events(io.BytesIO(b"".join(frame)), threading.Event()))
                        frame = []
            def wait_release():
                deadline = time.monotonic() + 2
                while gateway.approvals.active and time.monotonic() < deadline: time.sleep(0.005)
                self.assertEqual(gateway.approvals.active, set())
            def replace_cfg():
                pending = policy_path.with_suffix(".new")
                pending.write_text(json.dumps(cfg)); pending.replace(policy_path)
            try:
                with get() as response:
                    with self.assertRaises(HTTPError) as exc: get()
                    self.assertEqual(exc.exception.code, 429)
                    store.stage(EMBER, CLAUDE, "synthetic first event", message_id="synthetic-message-001",
                                conversation_id=conversation(), policy=policy)
                    first = read_event(response)
                    self.assertEqual(first["message_id"], "synthetic-message-001")
                    rotated = "public-synthetic-rotated-credential-000000"
                    cfg["participants"][CLAUDE]["sha256"] = hashlib.sha256(rotated.encode()).hexdigest()
                    replace_cfg()
                    # Changed principal fences an already-connected stream.
                    while response.readline(): pass
                wait_release()
                with self.assertRaises(HTTPError) as exc: get()
                self.assertEqual(exc.exception.code, 401)
                with get(rotated) as response:
                    replay = read_event(response)
                    self.assertEqual(replay, first)  # Stable identity on reconnect.
                wait_release()
                current = gateway.current_policy()
                store.stage(ADA, CLAUDE, "synthetic second event", message_id="synthetic-message-002",
                            conversation_id=conversation(CLAUDE, ADA), policy=current)
                with get(rotated, first["transport_cursor"]) as response:
                    second = read_event(response)
                    self.assertEqual(second["message_id"], "synthetic-message-002")
                wait_release()
                # Remove the first route: queued old metadata is not replayed.
                cfg["conversations"][conversation()]["routes"] = []; replace_cfg()
                with get(rotated) as response:
                    only = read_event(response)
                    self.assertEqual(only["message_id"], "synthetic-message-002")
                wait_release()
                self.assertEqual(store._row("synthetic-message-002")["status"], "queued")
                scoped = ScopedStore(store, CLAUDE, gateway.current_policy().agents[CLAUDE][1], gateway.current_policy())
                self.assertTrue(scoped.claim_message("synthetic-message-002", CLAUDE, "synthetic-native-claim")["claimed"])
                scoped.acknowledge("synthetic-message-002", CLAUDE, "synthetic-native-claim")
                self.assertFalse(scoped.claim_message("synthetic-message-002", CLAUDE, "synthetic-native-claim")["claimed"])
                self.assertEqual(gateway.approvals.pending(gateway.current_policy(), CLAUDE), [])
            finally:
                gateway.shutdown(); gateway.server_close(); thread.join(); store.close()


if __name__ == "__main__": unittest.main()
