"""Machine trust and session isolation; all tokens and data are synthetic."""
import copy
import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener
from babel.auth import Policy, ScopedStore
from babel.core import Store, BridgeError
from babel.gateway import Gateway
from babel.enrollment import change
from tests.test_participants import fixture, DOT, CODEX, SECOND, GROK, TOKENS

LAPTOP = "public-synthetic-laptop-machine-token-0000"
POP = "public-synthetic-pop-machine-token-0000000"
NATIVE = "01234567-89ab-cdef-0123-456789abcdef"
OTHER_NATIVE = "11234567-89ab-cdef-0123-456789abcdef"


def fixture_machines():
    cfg = fixture()
    cfg["approval"] = "automatic"
    cfg["machines"] = {
        mid: {"owner": "owner_a", "state": "active",
              "sha256": hashlib.sha256(token.encode()).hexdigest(), "coordinators": [DOT, GROK]}
        for mid, token in (("laptop", LAPTOP), ("pop", POP))}
    cfg["machine_sessions"] = {
        CODEX: {"machine": "laptop", "native_session": NATIVE},
        SECOND: {"machine": "pop", "native_session": NATIVE}}
    cfg["participants"][SECOND].pop("sha256")
    cfg["conversations"]["chat_second_01"] = {
        "state": "active", "participants": [SECOND, DOT],
        "routes": [{"sender": SECOND, "recipient": DOT}, {"sender": DOT, "recipient": SECOND}]}
    return cfg


class MachineTests(unittest.TestCase):
    def setUp(self):
        self.cfg = fixture_machines()
        self.policy = Policy(self.cfg)
        self.store = Store(":memory:")
        self.store.sync_policy(self.policy)

    def tearDown(self):
        self.store.close()

    def auth(self, token=LAPTOP, pid=CODEX, native=NATIVE, policy=None):
        return (policy or self.policy).authenticate_request("Bearer " + token, pid, native)

    def scoped(self, pid):
        return ScopedStore(self.store, pid, self.policy.agents[pid][1], self.policy)

    def test_authenticates_machine_then_pinned_session_not_hostname_or_label(self):
        self.assertEqual(self.auth(), CODEX)
        self.assertEqual(self.auth(POP, SECOND), SECOND)
        for token, pid, native in ((LAPTOP, SECOND, NATIVE), (POP, CODEX, NATIVE),
                                   (LAPTOP, DOT, NATIVE), (LAPTOP, CODEX, "minecraft"),
                                   (LAPTOP, CODEX, OTHER_NATIVE), ("public-unknown-machine-token-000000000", CODEX, NATIVE)):
            with self.subTest(pid=pid, native=native), self.assertRaises(BridgeError):
                self.auth(token, pid, native)

    def test_selectors_do_not_elevate_static_tokens_and_both_are_required(self):
        self.assertEqual(self.policy.authenticate_request("Bearer " + TOKENS[CODEX]), CODEX)
        for token, pid, native in ((TOKENS[CODEX], SECOND, NATIVE), (TOKENS[DOT], CODEX, NATIVE),
                                   (LAPTOP, CODEX, None), (LAPTOP, None, NATIVE), (LAPTOP, None, None)):
            with self.assertRaises(BridgeError):
                self.policy.authenticate_request("Bearer " + token, pid, native)

    def test_one_machine_can_have_distinct_clients_and_sessions_without_worker_tokens(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["machine_sessions"][SECOND].update(machine="laptop", native_session=OTHER_NATIVE)
        p = Policy(cfg)
        self.assertEqual(self.auth(LAPTOP, SECOND, OTHER_NATIVE, p), SECOND)
        self.assertEqual(self.auth(LAPTOP, CODEX, NATIVE, p), CODEX)
        with self.assertRaises(BridgeError): self.auth(LAPTOP, SECOND, NATIVE, p)
        self.assertNotIn(SECOND, p.credential_digests)

    def test_native_selectors_are_not_independent_authentication(self):
        # Deliberate threat-model test: anyone with a machine key can impersonate
        # any admitted session on that machine if they know its selector pair.
        cfg = copy.deepcopy(self.cfg)
        cfg["machine_sessions"][SECOND].update(machine="laptop", native_session=OTHER_NATIVE)
        self.assertEqual(self.auth(LAPTOP, SECOND, OTHER_NATIVE, Policy(cfg)), SECOND)

    def test_machine_and_worker_revocation_stop_access(self):
        for mutation in ("machine", "participant", "owner"):
            cfg = copy.deepcopy(self.cfg)
            if mutation == "machine": cfg["machines"]["laptop"]["state"] = "revoked"
            if mutation == "participant": cfg["participants"][CODEX]["state"] = "revoked"
            if mutation == "owner": cfg["owners"]["owner_a"]["enabled"] = False
            p = Policy(cfg)
            with self.assertRaises(BridgeError): self.auth(policy=p)
            with self.assertRaises(BridgeError): p.assert_active(CODEX)

    def test_routes_are_restricted_to_the_explicit_two_coordinators(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["conversations"]["forbidden_workers"] = {
            "state": "active", "participants": [CODEX, SECOND],
            "routes": [{"sender": CODEX, "recipient": SECOND}]}
        with self.assertRaises(BridgeError): Policy(cfg)

    def test_closed_conversation_cannot_smuggle_routes(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["conversations"]["chat_private_01"]["state"] = "closed"
        p = Policy(cfg)
        with self.assertRaises(BridgeError): p.assert_route("chat_private_01", CODEX, GROK)

    def test_policy_rejects_duplicate_native_binding_cross_owner_and_shared_worker_digest(self):
        mutations = [
            lambda c: c["machine_sessions"][SECOND].update(machine="laptop"),
            lambda c: c["machines"]["laptop"].update(owner="owner_b"),
            lambda c: c["machines"]["laptop"].update(sha256=c["participants"][CODEX]["sha256"]),
            lambda c: c["machines"]["pop"].update(sha256=c["machines"]["laptop"]["sha256"]),
            lambda c: c["machine_sessions"][CODEX].update(native_session="bad"),
            lambda c: c["machines"]["laptop"].update(coordinators=[DOT, CODEX]),
            lambda c: c["machine_sessions"][CODEX].update(machine="unknown"),
        ]
        for mutate in mutations:
            cfg = copy.deepcopy(self.cfg); mutate(cfg)
            with self.assertRaises(BridgeError): Policy(cfg)

    def test_machine_session_binding_cannot_be_reassigned_or_recycled(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["machine_sessions"][CODEX]["native_session"] = OTHER_NATIVE
        with self.assertRaises(BridgeError): self.store.sync_policy(Policy(cfg))
        cfg = copy.deepcopy(self.cfg); cfg["machine_sessions"].pop(CODEX)
        self.store.sync_policy(Policy(cfg))
        with self.assertRaises(BridgeError): self.store.sync_policy(self.policy)

    def test_native_session_and_machine_tombstones_cannot_be_reused(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["machines"]["laptop"]["state"] = "revoked"
        self.store.sync_policy(Policy(cfg))
        with self.assertRaises(BridgeError): self.store.sync_policy(self.policy)

    def test_retired_machine_credential_cannot_be_rotated_back_or_used_for_worker(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["machines"]["laptop"]["sha256"] = hashlib.sha256(b"public-synthetic-rotated-machine-token-000").hexdigest()
        self.store.sync_policy(Policy(cfg))
        with self.assertRaises(BridgeError): self.store.sync_policy(self.policy)
        cfg = copy.deepcopy(cfg)
        cfg["participants"][CODEX]["sha256"] = self.cfg["machines"]["laptop"]["sha256"]
        with self.assertRaises(BridgeError): self.store.sync_policy(Policy(cfg))

    def test_historical_worker_digest_cannot_be_promoted_to_machine(self):
        cfg = copy.deepcopy(self.cfg)
        old = cfg["participants"][CODEX].pop("sha256")
        cfg["machines"]["laptop"]["sha256"] = old
        with self.assertRaises(BridgeError): self.store.sync_policy(Policy(cfg))

    def test_mailboxes_claims_receipts_and_replies_remain_separate(self):
        row = self.scoped(GROK).stage(GROK, CODEX, text="synthetic request", message_id="machine-message-0001", conversation_id="chat_private_01")["message"]
        self.assertEqual(self.scoped(SECOND).inbox(SECOND), [])
        with self.assertRaises(BridgeError): self.scoped(SECOND).claim_message(row["id"], SECOND, "machine-claim-wrong")
        claim = self.scoped(CODEX).claim_message(row["id"], CODEX, "machine-claim-correct")
        self.assertTrue(claim["claimed"])
        self.scoped(CODEX).acknowledge(row["id"], CODEX, claim["claim_id"])
        reply = self.scoped(CODEX).stage(CODEX, GROK, text="synthetic reply", message_id="machine-reply-0001", reply_to=row["id"], conversation_id="chat_private_01")
        self.assertEqual(reply["message"]["source"], CODEX)
        self.assertEqual(reply["message"]["status"], "queued")

    def test_legacy_identity_fingerprints_and_data_survive_opt_in_addition(self):
        old = Policy(fixture())
        for pid in (DOT, GROK):
            # Their old routes in this fixture differ for SECOND; compare the
            # same configuration with optional machine fields removed instead.
            cfg = copy.deepcopy(self.cfg)
            cfg.pop("machines"); cfg.pop("machine_sessions")
            cfg["participants"][SECOND]["sha256"] = hashlib.sha256(TOKENS[SECOND].encode()).hexdigest()
            self.assertEqual(Policy(cfg).agents[pid][0], self.policy.agents[pid][0])
        self.assertEqual(old.authenticate("Bearer " + TOKENS[CODEX]), CODEX)
        self.assertEqual(self.policy.authenticate("Bearer " + TOKENS[CODEX]), CODEX)

    def test_host_only_machine_and_native_session_enrollment_does_not_issue_worker_key(self):
        cfg = fixture()
        cfg = change(cfg, "machine", machine="approved_pop", owner="owner_a",
                     sha256=hashlib.sha256(POP.encode()).hexdigest(), coordinators=[DOT,GROK])
        cfg = change(cfg, "invite", owner="owner_a", client="codex", session="minecraft_01")
        pid = "owner_a.codex.minecraft_01"
        cfg = change(cfg, "bind-machine", participant=pid, machine="approved_pop", native_session=NATIVE)
        cfg = change(cfg, "activate", participant=pid, accepted=True)
        self.assertNotIn("sha256", cfg["participants"][pid])
        self.assertNotIn(pid, Policy(cfg).credential_digests)
        with self.assertRaises(BridgeError):
            change(cfg, "bind-machine", participant=pid, machine="approved_pop", native_session=OTHER_NATIVE)
        revoked = change(cfg, "revoke-machine", machine="approved_pop")
        with self.assertRaises(BridgeError): Policy(revoked).assert_active(pid)

    def test_schema_upgrade_preserves_all_existing_message_receipt_and_binding_rows(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bridge.sqlite3"
            store = Store(path)
            p = Policy(fixture()); store.sync_policy(p)
            store.policy_provider = lambda: p
            scoped = ScopedStore(store, CODEX, p.agents[CODEX][1], p)
            row = scoped.stage(CODEX, GROK, text="synthetic retained history", message_id="migration-message-01", conversation_id="chat_private_01")["message"]
            store.approve(row["id"])
            recipient = ScopedStore(store,GROK,p.agents[GROK][1],p)
            recipient.claim_message(row["id"],GROK,"migration-claim-01")
            recipient.acknowledge(row["id"],GROK,"migration-claim-01")
            tables = ("messages","events","message_claims","subscriptions","outbox","participant_bindings","credential_bindings","oauth_bindings")
            before = {t:[dict(r) for r in store.db.execute("SELECT * FROM "+t)] for t in tables}
            store.close()
            db = sqlite3.connect(path)
            for t in ("machine_session_bindings","machine_credential_bindings","machine_bindings"):
                db.execute("DROP TABLE "+t)
            db.execute("PRAGMA user_version=4"); db.commit(); db.close()
            store = Store(path)
            try:
                store.sync_policy(p)
                after = {t:[dict(r) for r in store.db.execute("SELECT * FROM "+t)] for t in tables}
                self.assertEqual(before,after)
                self.assertEqual(store.db.execute("PRAGMA user_version").fetchone()[0],5)
            finally: store.close()

    def test_http_discovery_admin_auth_and_hot_binding_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"; path.write_text(json.dumps(self.cfg))
            server = Gateway(0, Policy.load(path), "https://bridge.example.com", self.store)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            opener = build_opener(ProxyHandler({}))
            def call(route="/mcp/v1", token=LAPTOP, pid=CODEX, native=NATIVE):
                headers = {"Host": "bridge.example.com", "X-Forwarded-Proto": "https",
                           "Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
                if token is not None: headers["Authorization"] = "Bearer " + token
                if pid is not None: headers["Babel-Participant"] = pid
                if native is not None: headers["Babel-Native-Session"] = native
                discovery = route.startswith("/.well-known/")
                req = Request("http://127.0.0.1:" + str(server.port) + route,
                              data=None if discovery else b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}', headers=headers)
                try: response = opener.open(req, timeout=3)
                except HTTPError as exc: response = exc
                with response: return response.status, response.read()
            try:
                self.assertEqual(call()[0], 200)
                self.assertEqual(call(pid=SECOND)[0], 403)
                self.assertEqual(call(token=None)[0], 401)
                self.assertEqual(call("/.well-known/oauth-protected-resource", token=None, pid=None, native=None)[0], 200)
                for route in ("/api/policy", "/api/participants", "/enroll"):
                    self.assertEqual(call(route)[0], 404)
                self.assertEqual(call(token=TOKENS[CODEX], pid=None, native=None)[0], 200)
                import http.client
                client = http.client.HTTPConnection('127.0.0.1', server.port, timeout=3)
                client.putrequest('POST', '/mcp/v1', skip_host=True)
                for key, value in [('Host','bridge.example.com'),('X-Forwarded-Proto','https'),
                                   ('Authorization','Bearer '+LAPTOP),('Babel-Participant',CODEX),
                                   ('Babel-Participant',CODEX),('Babel-Native-Session',NATIVE),('Content-Length','0')]:
                    client.putheader(key,value)
                client.endheaders()
                self.assertEqual(client.getresponse().status,403)
                client.close()
                cfg = copy.deepcopy(self.cfg); cfg["machines"]["laptop"]["state"] = "revoked"
                path.write_text(json.dumps(cfg))
                self.assertEqual(call()[0], 403)
            finally:
                server.shutdown(); server.server_close(); thread.join(3)


class MachineOAuthTests(unittest.TestCase):
    def test_existing_oauth_client_remains_valid_and_cannot_select_worker(self):
        from tests.test_participants import ParticipantOAuthTests, jwt
        if jwt is None: self.skipTest('Optional OAuth dependencies unavailable')
        fixture = ParticipantOAuthTests()
        fixture.setUpClass(); fixture.setUp()
        cfg = fixture_machines(); cfg['participants'][DOT].pop('sha256')
        cfg['oauth'] = fixture.cfg['oauth']
        p = fixture.policy(cfg)
        self.assertEqual(p.authenticate_request('Bearer '+fixture.token()),DOT)
        self.assertEqual(p.authenticate_request('Bearer '+LAPTOP,CODEX,NATIVE),CODEX)
        self.assertEqual(p.authenticate_request('Bearer '+TOKENS[GROK]),GROK)
        with self.assertRaises(BridgeError): p.authenticate_request('Bearer '+fixture.token(),CODEX,NATIVE)


if __name__ == "__main__":
    unittest.main()
