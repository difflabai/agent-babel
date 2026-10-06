"""No real credentials: exact allowlisted names with public synthetic test tokens."""
import base64
import copy
import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler
from babel.auth import Policy, ScopedStore
from babel.core import BridgeError, Store
from babel.gateway import Gateway
from babel.mcp import dispatch
from babel.synthetic import SyntheticTransfers, SISTERS, CONVERSATION, fixture, digest, TTL, MAX_BYTES

EMBER = "bits255.dots.ada_20261002"
ADA = "bits255.grokbot.grok_20261002"
WORKER = "bits255.codex.synthetic_worker"
TOKENS = {role: "public-synthetic-test-token-" + str(n).zfill(12)
          for n, role in enumerate((EMBER, ADA, WORKER))}

def policy_fixture():
    now = int(time.time())
    participants = {}
    for role, token in TOKENS.items():
        owner, client, session = role.split(".")
        participants[role] = {"owner": owner, "client": client, "session": session,
            "state": "active", "accepted": True, "activated_at": now - 10, "expires": None,
            "sha256": hashlib.sha256(token.encode()).hexdigest()}
    return {"schema_version": 3, "owners": {"bits255": {"enabled": True}},
        "participants": participants, "conversations": {CONVERSATION: {
            "state": "active", "participants": [EMBER, ADA], "routes": [
                {"sender": EMBER, "recipient": ADA}, {"sender": ADA, "recipient": EMBER}]}}}

class SyntheticTests(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(policy_fixture())
        self.store = Store(":memory:")
        self.store.sync_policy(self.policy)
        self.now = 1000.0
        self.trial = SyntheticTransfers(lambda: self.now)
    def tearDown(self):
        self.store.close()
    def scoped(self, role=EMBER, policy=None):
        policy = policy or self.policy
        scope = ScopedStore(self.store, role, policy.agents[role][1], policy)
        scope.synthetic = self.trial
        return scope
    def call(self, action, role=EMBER, mid="synthetic-test-001", **args):
        return self.trial.call(self.scoped(role), {"action": action, "transfer_id": mid, **args})
    def begin(self, size=16384, **args):
        return self.call("begin", recipient=ADA, size=size, sha256=digest(fixture(0, size)), **args)
    def put(self, offset, size=16384, **args):
        chunk = fixture(offset, min(4096, size - offset))
        return self.call("put", offset=offset, data_base64=base64.b64encode(chunk).decode(),
                         sha256=digest(chunk), **args)
    def expect_error(self, status, fn):
        with self.assertRaises(BridgeError) as error:
            fn()
        self.assertEqual(error.exception.status, status)
    def test_two_principal_round_trip_partial_final_chunk_and_retry(self):
        size = 16385
        manifest = self.begin(size)
        self.assertEqual(self.begin(size), manifest)
        for offset in range(0, size, 4096):
            self.put(offset, size)
            self.put(offset, size)
        self.call("commit"); self.call("commit")
        for role in SISTERS:
            output = bytearray()
            for offset in range(0, size, 4096):
                result = self.call("get", role=role, offset=offset)
                chunk = base64.b64decode(result["data_base64"], validate=True)
                self.assertEqual(digest(chunk), result["sha256"])
                self.assertEqual(len(chunk), result["length"])
                output.extend(chunk)
            self.assertEqual(bytes(output), fixture(0, size))
            self.assertEqual(digest(output), manifest["sha256"])
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 0)
    def test_unauthorized_worker_recipient_source_and_disabled(self):
        self.begin()
        self.expect_error(403, lambda: self.call("status", role=WORKER))
        self.expect_error(403, lambda: self.call("commit", role=ADA))
        self.expect_error(400, lambda: self.call("begin", mid="wrong-recipient-01", recipient=WORKER,
                           size=1, sha256=digest(fixture(0, 1))))
        self.expect_error(404, lambda: self.call("begin", role=ADA, recipient=EMBER,
                           size=16384, sha256=digest(fixture(0, 16384))))
        for role in (EMBER, WORKER):
            scope = self.scoped(role)
            for enabled in (False, True):
                scope.synthetic = self.trial if enabled else None
                tools = dispatch(scope, role, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
                self.assertEqual(any(t["name"] == "synthetic_transfer" for t in tools), enabled and role == EMBER)
                if not enabled:
                    result = dispatch(scope, role, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "synthetic_transfer", "arguments": {"action": "status", "transfer_id": "synthetic-test-001"}}})
                    self.assertTrue(result["result"]["isError"])
    def test_expired_data_erased_and_id_not_reopened(self):
        self.begin(); self.put(0)
        self.now += TTL
        self.trial.expire()
        self.assertEqual(self.trial.records["synthetic-test-001"]["data"], b"")
        self.expect_error(410, lambda: self.call("get", offset=0))
        self.expect_error(410, self.begin)
    def test_conflicting_offset_truncation_uncommitted_and_manifest(self):
        self.begin()
        self.expect_error(409, lambda: self.put(4096))
        self.expect_error(409, lambda: self.call("commit"))
        self.put(0)
        self.expect_error(409, lambda: self.call("get", offset=0))
        self.expect_error(409, lambda: self.begin(1))
        self.expect_error(400, lambda: self.call("put", offset=0, data_base64="AA==", sha256=digest(b"\0")))
    def test_real_bytes_bad_hash_base64_path_url_and_bool_rejected(self):
        self.begin()
        data = b"real-file-bytes" * 300
        data = data[:4096].ljust(4096, b"x")
        self.expect_error(400, lambda: self.call("put", offset=0,
            data_base64=base64.b64encode(data).decode(), sha256=digest(data)))
        self.expect_error(400, lambda: self.call("put", offset=0, data_base64="!" * 10, sha256="0" * 64))
        self.expect_error(400, lambda: self.call("put", offset=True, data_base64="", sha256="0" * 64))
        self.expect_error(400, lambda: self.call("begin", mid="boolean-size-001", recipient=ADA,
            size=True, sha256=digest(fixture(0, 1))))
        for extra in ({"path": "/etc/passwd"}, {"url": "https://example.com"}, {"source": ADA}):
            self.expect_error(400, lambda: self.call("status", **extra))
    def test_capacity_delete_restart_and_size_limits(self):
        for n in range(8):
            self.begin(MAX_BYTES, mid="capacity-test-" + str(n))
        self.expect_error(429, lambda: self.begin(mid="capacity-test-extra"))
        self.call("delete", role=ADA, mid="capacity-test-0")
        self.call("delete", role=ADA, mid="capacity-test-0")
        self.begin(mid="capacity-test-extra")
        self.expect_error(400, lambda: self.begin(MAX_BYTES + 1, mid="too-big-test-001"))
        self.expect_error(410, lambda: self.call("status", mid="capacity-test-0"))
        self.trial = SyntheticTransfers(lambda: self.now)
        self.expect_error(404, lambda: self.call("status", mid="capacity-test-extra"))
    def test_route_and_participant_revocation_checked_each_call(self):
        self.begin()
        for mode in ("route", "participant"):
            cfg = copy.deepcopy(policy_fixture())
            if mode == "route":
                cfg["conversations"][CONVERSATION]["routes"] = []
            else:
                cfg["participants"][ADA]["state"] = "closed"
            policy = Policy(cfg)
            self.expect_error(403, lambda: self.trial.call(self.scoped(policy=policy),
                {"action": "status", "transfer_id": "synthetic-test-001"}))
    def test_concurrent_retry_does_not_duplicate_bytes(self):
        self.begin()
        errors = []
        def put():
            try:
                self.put(0)
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=put) for _ in range(8)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.call("status")["received_bytes"], 4096)
    def test_metadata_is_bounded_and_idle_server_loop_expires_payloads(self):
        for n in range(512):
            mid = "bounded-manifest-" + str(n)
            self.begin(1, mid=mid)
            self.call("delete", mid=mid)
        self.expect_error(429, lambda: self.begin(mid="bounded-manifest-extra"))
        self.assertEqual(len(self.trial.records), 512)
        server = Gateway(0, self.policy, "https://bridge.example.com", self.store, synthetic_trial=True)
        try:
            self.trial = server.synthetic
            self.trial.clock = lambda: self.now
            self.begin(); self.put(0)
            self.now += TTL
            server.service_actions()
            self.assertEqual(self.trial.records["synthetic-test-001"]["data"], b"")
        finally:
            server.server_close()
    def test_live_policy_reload_revokes_access(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            cfg = policy_fixture(); path.write_text(json.dumps(cfg))
            scope = self.scoped(policy=Policy.load(path))
            self.trial.call(scope, {"action": "begin", "transfer_id": "live-revoke-001", "recipient": ADA,
                                   "size": 1, "sha256": digest(fixture(0, 1))})
            cfg["conversations"][CONVERSATION]["routes"] = []
            path.write_text(json.dumps(cfg))
            self.expect_error(403, lambda: self.trial.call(scope, {"action": "status", "transfer_id": "live-revoke-001"}))

class SyntheticHTTPTests(unittest.TestCase):
    def test_authenticated_http_16k_round_trip_and_auth_boundary(self):
        store = Store(":memory:")
        server = Gateway(0, Policy(policy_fixture()), "https://bridge.example.com", store, synthetic_trial=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        opener = build_opener(ProxyHandler({}))
        def rpc(method, args=None, role=EMBER, modern=False, anonymous=False):
            params = {} if args is None else {"name": "synthetic_transfer", "arguments": args}
            headers = {"Host": "bridge.example.com", "X-Forwarded-Proto": "https",
                       "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
            if not anonymous: headers["Authorization"] = "Bearer " + TOKENS[role]
            if modern:
                params["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                   "io.modelcontextprotocol/clientCapabilities": {}}
                headers.update({"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method})
                if args is not None: headers["Mcp-Name"] = "synthetic_transfer"
            request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            req = Request("http://127.0.0.1:" + str(server.port) + ("/mcp" if modern else "/mcp/v1"),
                          data=json.dumps(request).encode(), headers=headers)
            with opener.open(req, timeout=5) as response:
                return json.load(response)["result"]
        def call(action, role=EMBER, **args):
            result = rpc("tools/call", {"action": action, "transfer_id": "http-roundtrip-001", **args}, role=role, modern=True)
            self.assertFalse(result["isError"], result)
            return json.loads(result["content"][0]["text"])
        try:
            with self.assertRaises(HTTPError) as exc: rpc("tools/list", anonymous=True)
            self.assertEqual(exc.exception.code, 401)
            for modern in (False, True):
                for role in (EMBER, ADA, WORKER):
                    catalog = rpc("tools/list", role=role, modern=modern)["tools"]
                    self.assertEqual(any(t["name"] == "synthetic_transfer" for t in catalog), role in SISTERS)
            denied = rpc("tools/call", {"action": "status", "transfer_id": "http-roundtrip-001"}, role=WORKER)
            self.assertTrue(denied["isError"])
            full = fixture(0, 16384)
            call("begin", recipient=ADA, size=len(full), sha256=digest(full))
            for offset in range(0, len(full), 4096):
                chunk = full[offset:offset + 4096]
                call("put", offset=offset, data_base64=base64.b64encode(chunk).decode(), sha256=digest(chunk))
            call("commit")
            downloaded = bytearray()
            for offset in range(0, len(full), 4096):
                chunk = call("get", role=ADA, offset=offset)
                downloaded.extend(base64.b64decode(chunk["data_base64"], validate=True))
            self.assertEqual(digest(downloaded), digest(full))
            call("delete", role=ADA)
        finally:
            server.shutdown(); server.server_close(); thread.join(); store.close()
