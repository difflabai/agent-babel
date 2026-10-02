import json
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler
from babel.core import ROOT, BridgeError, Store, MAX_HOPS
from babel.adapters import LIVE_ADAPTERS, ManualAdapter, MockAdapter
from babel.mcp import dispatch
from babel.server import Server

class StoreTests(unittest.TestCase):
    def setUp(self): self.store = Store(":memory:")
    def tearDown(self): self.store.close()
    def stage(self, **kw):
        data = {"source": "ada", "recipient": "grokbot", "text": "user-selected text"}
        data.update(kw)
        return self.store.stage(**data)["message"]

    def test_draft_approval_receive_and_acknowledgment(self):
        row = self.stage()
        self.assertEqual(self.store.inbox("grokbot"), [])
        with self.assertRaises(BridgeError): self.store.acknowledge(row["id"], "grokbot")
        self.store.approve(row["id"])
        self.assertEqual(len(self.store.inbox("grokbot")), 1)
        self.assertEqual(len(self.store.inbox("grokbot")), 1)
        with self.assertRaises(BridgeError): self.store.acknowledge(row["id"], "ada")
        ack = self.store.acknowledge(row["id"], "grokbot")
        self.assertEqual(ack["status"], "acknowledged")
        self.assertEqual(self.store.inbox("grokbot"), [])
        self.store.acknowledge(row["id"], "grokbot")
        self.assertEqual(len([e for e in self.store.events(row["id"]) if e["action"] == "acknowledged"]), 1)

    def test_deduplicate_and_reject_changed_content(self):
        row = self.stage(message_id="stable-message-001")
        duplicate = self.store.stage("ada", "grokbot", row["text"], message_id=row["id"])
        self.assertTrue(duplicate["duplicate"])
        with self.assertRaises(BridgeError) as error:
            self.stage(message_id=row["id"], text="different")
        self.assertEqual(error.exception.status, 409)
        self.assertEqual(len(self.store.history()), 1)

    def test_manual_export_and_mock_never_claim_delivery(self):
        row = self.stage()
        with self.assertRaises(BridgeError): ManualAdapter(self.store).receive(row["id"])
        self.store.approve(row["id"])
        packet = ManualAdapter(self.store).receive(row["id"])
        self.assertIn("no message was sent", packet["notice"])
        self.assertEqual(packet["packet"]["id"], row["id"])
        self.assertTrue(MockAdapter(self.store).receive(row["id"])["mock"])
        self.assertEqual(self.store.inbox("grokbot")[0]["status"], "queued")
        self.assertIsNone(self.store.inbox("grokbot")[0]["acknowledged"])
        for adapter in LIVE_ADAPTERS.values():
            with self.assertRaises(BridgeError): adapter.receive(row["id"])

    def test_manual_receipt_is_labeled(self):
        row = self.stage()
        self.store.approve(row["id"])
        ack = self.store.acknowledge(row["id"], "grokbot", "manual-operator")
        self.assertEqual(ack["receipt"], "manual-operator")

    def test_thread_hops_and_reply_route(self):
        row = self.stage()
        with self.assertRaises(BridgeError):
            self.stage(source="grokbot", recipient="ada", reply_to=row["id"])
        self.store.approve(row["id"])
        with self.assertRaises(BridgeError):
            self.stage(source="muse", recipient="ada", reply_to=row["id"])
        root = row["root_id"]
        for hop in range(2, MAX_HOPS + 1):
            row = self.stage(source=row["recipient"], recipient=row["source"], reply_to=row["id"])
            self.assertEqual(row["hops"], hop)
            self.assertEqual(row["root_id"], root)
            self.store.approve(row["id"])
        with self.assertRaises(BridgeError):
            self.stage(source=row["recipient"], recipient=row["source"], reply_to=row["id"])

    def test_durable_rate_limit_and_retry_exemption(self):
        for n in range(10): self.stage(message_id="rate-message-" + str(n))
        self.assertTrue(self.store.stage("ada", "grokbot", "user-selected text",
                                       message_id="rate-message-0")["duplicate"])
        with self.assertRaises(BridgeError) as error: self.stage()
        self.assertEqual(error.exception.status, 429)
        self.stage(source="grokbot", recipient="ada")

    def test_utf8_payload_ids_and_limits(self):
        self.stage(text="🙂" * 4096)
        for data in ({"text": "🙂" * 4097}, {"text": " "}, {"text": 42},
                     {"message_id": "../../secret"}, {"recipient": "other"},
                     {"recipient": "ada"}, {"reply_to": "missing-parent-000"}):
            with self.assertRaises(BridgeError): self.stage(**data)
        for limit in (0, 51, True, "1"):
            with self.assertRaises(BridgeError): self.store.inbox("ada", limit)

    def test_cancellation(self):
        row = self.stage()
        self.store.approve(row["id"])
        self.store.cancel(row["id"])
        self.store.cancel(row["id"])
        self.assertFalse(self.store.inbox("grokbot"))
        with self.assertRaises(BridgeError): self.store.approve(row["id"])
        with self.assertRaises(BridgeError): self.store.acknowledge(row["id"], "grokbot")

    def test_history_is_scoped_and_paginated(self):
        outgoing = self.stage()
        self.stage(source="grokbot", recipient="muse")
        self.assertEqual(len(self.store.history(role="ada")), 1)
        self.assertEqual(self.store.history(role="grokbot")[0]["recipient"], "muse")
        self.assertEqual(len(self.store.history(role="grokbot")), 1)
        self.store.approve(outgoing["id"])
        self.assertEqual(len(self.store.history(role="grokbot")), 2)
        latest = self.store.history(limit=1)[0]
        older = self.store.history(before=latest["seq"])
        self.assertEqual(older[0]["id"], outgoing["id"])

    def test_persistence_and_restart_keep_queue_and_dedupe(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".test-") as folder:
            db = Path(folder) / "bridge.sqlite3"
            first = Store(db)
            row = first.stage("ada", "grokbot", "restart test", message_id="persist-message-001")["message"]
            first.approve(row["id"])
            for n in range(9):
                first.stage("ada", "grokbot", "rate persists", message_id="persist-rate-" + str(n))
            first.close()
            second = Store(db)
            try:
                self.assertEqual(second.inbox("grokbot")[0]["text"], "restart test")
                self.assertTrue(second.stage("ada", "grokbot", "restart test",
                                             message_id=row["id"])["duplicate"])
                self.assertEqual(len(second.events(row["id"])), 2)
                with self.assertRaises(BridgeError) as error:
                    second.stage("ada", "grokbot", "blocked after restart")
                self.assertEqual(error.exception.status, 429)
                self.assertEqual(db.stat().st_mode & 0o777, 0o600)
            finally: second.close()

    def test_schema_upgrade_preserves_messages_and_future_schema_fails_closed(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".test-") as folder:
            path=Path(folder)/"bridge.sqlite3"
            original=Store(path)
            row=original.stage("ada","grokbot","synthetic migration",message_id="migration-message-01")["message"]
            original.approve(row["id"]);original.close()
            db=sqlite3.connect(path)
            for table in ("message_claims","outbox","subscriptions"):
                db.execute("DROP TABLE "+table)
            db.execute("PRAGMA user_version=1");db.commit();db.close()
            migrated=Store(path)
            self.assertEqual(migrated.inbox("grokbot")[0]["id"],row["id"])
            self.assertEqual(migrated.db.execute("PRAGMA user_version").fetchone()[0],4)
            migrated.close()
            db=sqlite3.connect(path);db.execute("PRAGMA user_version=99");db.commit();db.close()
            with self.assertRaises(BridgeError): Store(path)

    def test_two_connections_deduplicate_concurrent_retry(self):
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".test-") as folder:
            db = Path(folder) / "bridge.sqlite3"
            stores = [Store(db), Store(db)]
            results = []
            def write(store):
                results.append(store.stage("ada", "grokbot", "same", message_id="concurrent-message-001"))
            threads = [threading.Thread(target=write, args=(s,)) for s in stores]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            try:
                self.assertEqual(len(results), 2)
                self.assertEqual(sum(r["duplicate"] for r in results), 1)
                self.assertEqual(len(stores[0].history()), 1)
            finally:
                for s in stores: s.close()

class MCPTests(unittest.TestCase):
    def setUp(self): self.store = Store(":memory:")
    def tearDown(self): self.store.close()
    def rpc(self, method, params=None, role="ada"):
        return dispatch(self.store, role, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    def call(self, name, args=None, role="ada"):
        return self.rpc("tools/call", {"name": name, "arguments": args or {}}, role)["result"]

    def test_initialize_tools_and_no_approval_or_events(self):
        result = self.rpc("initialize", {"protocolVersion": "2025-11-25"})["result"]
        self.assertEqual(result["protocolVersion"], "2025-11-25")
        self.assertNotIn("events", result["capabilities"])
        tools = self.rpc("tools/list")["result"]["tools"]
        self.assertEqual({t["name"] for t in tools},
                         {"list_contacts", "stage_message", "receive_messages", "acknowledge_message", "claim_message", "message_status", "bridge_history"})
        self.assertIn("error", self.rpc("events/subscribe"))
        self.assertTrue(self.call("approve_message", {"message_id": "fake-message-001"})["isError"])

    def test_role_is_bound_and_drafts_require_operator_approval(self):
        data = {"recipient": "grokbot", "text": "MCP draft", "message_id": "mcp-message-001"}
        response = self.call("stage_message", data)
        row = json.loads(response["content"][0]["text"])["message"]
        self.assertEqual(row["source"], "ada")
        self.assertEqual(row["provenance"], "mcp")
        self.assertTrue(self.call("stage_message", {**data, "source": "grokbot"})["isError"])
        inbox = self.call("receive_messages", role="grokbot")
        self.assertFalse(json.loads(inbox["content"][0]["text"])["messages"])
        self.store.approve(row["id"])
        inbox = self.call("receive_messages", role="grokbot")
        self.assertEqual(json.loads(inbox["content"][0]["text"])["messages"][0]["id"], row["id"])
        self.assertTrue(self.call("acknowledge_message", {"message_id": row["id"]})["isError"])
        self.assertFalse(self.call("acknowledge_message", {"message_id": row["id"]}, "grokbot")["isError"])

    def test_invalid_jsonrpc_and_arguments(self):
        for request in ([], None, {"method": "ping"}, {"jsonrpc": "2.0", "method": 1},
                        {"jsonrpc": "2.0", "id": [], "method": "ping"}):
            self.assertIn("error", dispatch(self.store, "ada", request))
        self.assertTrue(self.call("stage_message", {"recipient": "grokbot", "text": "missing ID"})["isError"])
        self.assertTrue(self.call("stage_message", {"recipient": "grokbot", "text": "null ID",
                                                   "message_id": None})["isError"])
        self.assertTrue(self.call("receive_messages", {"limit": True})["isError"])
        self.assertIsNone(dispatch(self.store, "ada", {"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_stdio_real_process_without_creating_message_history(self):
        frames = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "ping"},
        ]
        with tempfile.TemporaryDirectory(dir=ROOT, prefix=".test-stdio-") as folder:
            result = subprocess.run([sys.executable, str(ROOT / "mcp_server.py"), "mcp", "--agent", "ada"],
                                cwd=ROOT, input="\n".join(json.dumps(f) for f in frames) + "\n",
                                text=True, capture_output=True, timeout=5, check=True, env={**os.environ, "BABEL_DATA_DIR": folder})
        responses = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([r["id"] for r in responses], [1, 2, 3])
        self.assertEqual(len(responses[1]["result"]["tools"]), 7)
        self.assertEqual(result.stderr, "")

class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = Store(":memory:")
        cls.server = Server(0, cls.store)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.server.port)
        cls.opener = build_opener(ProxyHandler({}))
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(); cls.store.close()
    def request(self, path, data=None, headers=None, method=None):
        hdr = {"Content-Type": "application/json"}
        hdr.update(headers or {})
        body = None if data is None else json.dumps(data).encode()
        request = Request(self.base + path, data=body, headers=hdr, method=method)
        try:
            response = self.opener.open(request, timeout=3)
        except HTTPError as exc: response = exc
        with response: return response.status, response.read(), dict(response.headers)

    def test_health_and_static_assets(self):
        status, body, headers = self.request("/api/health")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["live_adapters"])
        self.assertFalse(json.loads(body)["events"])
        for path in ("/", "/app.js", "/style.css"):
            status, body, headers = self.request(path)
            self.assertEqual(status, 200)
            self.assertGreater(len(body), 100)
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertIn(b"Real apps are not connected", self.request("/")[1])

    def test_foreign_origins_hosts_and_missing_csrf_denied(self):
        for headers in ({"Origin": "https://evil.example"}, {"Origin": "null"},
                        {"Host": "evil.example"}, {"Sec-Fetch-Site": "cross-site"}):
            self.assertEqual(self.request("/api/session", headers=headers)[0], 403)
            self.assertEqual(self.request("/mcp", {}, headers=headers)[0], 403)
        self.assertEqual(self.request("/api/stage", {})[0], 403)
        self.assertEqual(self.request("/api/stage", {}, {"X-Babel-CSRF": "wrong"})[0], 403)
        self.assertEqual(self.request("/../README.md")[0], 404)
        self.assertEqual(self.request("/api/history?file=/etc/passwd")[0], 400)

    def test_mcp_headers_notifications_and_invalid_protocol(self):
        hdr = {"Accept": "application/json, text/event-stream"}
        rpc = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-11-25"}}
        self.assertEqual(self.request("/mcp/ada", rpc)[0], 406)
        status, body, _ = self.request("/mcp/ada", rpc, hdr)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(self.request("/mcp/ada", rpc, {**hdr, "MCP-Protocol-Version": "2026-07-28"})[0], 400)
        self.assertEqual(self.request("/mcp/ada", rpc, {**hdr, "MCP-Protocol-Version": "2024-11-05"})[0], 400)
        status, body, _ = self.request("/mcp/ada", {"jsonrpc": "2.0", "method": "notifications/initialized"}, hdr)
        self.assertEqual(status, 202); self.assertEqual(body, b"")
        self.assertEqual(self.request("/mcp/ada")[0], 405)
        self.assertEqual(self.request("/mcp/ada", method="DELETE")[0], 405)

    def test_manual_ui_flow_round_trip_both_directions(self):
        csrf = json.loads(self.request("/api/session")[1])["csrf"]
        headers = {"X-Babel-CSRF": csrf, "Origin": self.base}
        first_id = "http-ui-message-001"
        for source, recipient, mid, parent in (
                ("ada", "grokbot", first_id, None),
                ("grokbot", "ada", "http-ui-message-002", first_id)):
            data = {"source": source, "recipient": recipient, "text": "manually selected " + source,
                    "message_id": mid}
            if parent: data["reply_to"] = parent
            self.assertEqual(self.request("/api/stage", data, headers)[0], 200)
            inbox = self.request("/api/receive", {"recipient": recipient}, headers)
            self.assertFalse(any(r["id"] == mid for r in json.loads(inbox[1])["messages"]))
            self.assertEqual(self.request("/api/approve", {"message_id": mid}, headers)[0], 200)
            packet = json.loads(self.request("/api/export", {"message_id": mid}, headers)[1])
            self.assertEqual(packet["packet"]["id"], mid)
            inbox = json.loads(self.request("/api/receive", {"recipient": recipient}, headers)[1])
            self.assertTrue(any(r["id"] == mid for r in inbox["messages"]))
            self.assertEqual(self.request("/api/acknowledge", {"message_id": mid, "recipient": recipient}, headers)[0], 200)

    def test_bounded_http_body_and_content_type(self):
        csrf = self.server.csrf
        self.assertEqual(self.request("/api/stage", {"text": "x" * 66000},
                                      {"X-Babel-CSRF": csrf})[0], 413)
        self.assertEqual(self.request("/api/stage", {},
                                      {"X-Babel-CSRF": csrf, "Content-Type": "text/plain"})[0], 415)

if __name__ == "__main__":
    unittest.main()
