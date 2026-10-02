"""All credentials and callbacks here are public synthetic fixtures, never live."""
import base64
from email.message import Message
from http.client import HTTPResponse
import hashlib
import hmac
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener
from babel.auth import Policy, ScopedStore, public_origin
from babel.core import ROOT, Store, BridgeError
from babel.events import EventService, EventError, EVENT_NAME
from babel.gateway import Gateway
from babel import mcp2
from babel.wake import WakeConfig, CallbackError, GrokWebhookAdapter, public_addresses, signed_headers, key_bytes

ADA = "public-test-fixture-ada-credential-000000"
GROK = "public-test-fixture-grok-credential-00000"
KEY = "whsec_" + base64.b64encode(b"public synthetic signing fixture!").decode()
def policy():
    return Policy({"schema_version":1, "agents":{
        "ada":{"sha256":hashlib.sha256(ADA.encode()).hexdigest(), "recipients":["grokbot"]},
        "grokbot":{"sha256":hashlib.sha256(GROK.encode()).hexdigest(), "recipients":["ada"]}}})
def config(grok=False):
    value = {"enabled": True, "callback_hosts":{"ada":["ada.example.com"],"grokbot":["grok.example.com"]}}
    if grok:
        value["grok"]={"enabled":True,"url":"https://grok.example.com/routine", "sender_key":GROK}
    return WakeConfig(value)

class FakeTransport:
    def __init__(self):
        self.calls = []
        self.status = 200
        self.failure = None
        self.bad_challenge = False
    def post(self, role, url, body, headers):
        self.calls.append((role, url, body, headers))
        if self.failure:
            raise CallbackError(self.failure)
        value=json.loads(body)
        response = json.dumps({"challenge":"bad" if self.bad_challenge else value.get("challenge")}).encode()
        return self.status, response

class AuthTests(unittest.TestCase):
    def test_policy_fail_closed_and_role_binding(self):
        p=policy()
        self.assertEqual(p.authenticate("Bearer "+ADA),"ada")
        for header in (None, ADA, "Bearer wrong", "Bearer "+ADA+"\n", "Bearer "+GROK+"?q=1"):
            with self.assertRaises(BridgeError): p.authenticate(header)
        for entry in ({}, {"schema_version":1,"agents":{}},
                      {"schema_version":1,"agents":{"ada":{"sha256":"<placeholder>","recipients":["grokbot"]}}}):
            with self.assertRaises(BridgeError): Policy(entry)
        p=policy()
        for _ in range(120): p.authenticate("Bearer "+ADA)
        with self.assertRaises(BridgeError) as exc: p.authenticate("Bearer "+ADA)
        self.assertEqual(exc.exception.status,429)

    def test_scope_and_hidden_drafts(self):
        store=Store(":memory:")
        try:
            ada=ScopedStore(store,"ada",{"grokbot"})
            grok=ScopedStore(store,"grokbot",{"ada"})
            row=ada.stage("ada","grokbot",text="secret draft",message_id="scope-message-001")["message"]
            for action in (lambda:grok.message_status(row["id"],"grokbot"),
                           lambda:grok.acknowledge(row["id"],"grokbot"),
                           lambda:ada.stage("ada","muse",text="forbidden"),
                           lambda:ada.inbox("grokbot")):
                with self.assertRaises(BridgeError): action()
            store.approve(row["id"])
            with self.assertRaises(BridgeError): grok.acknowledge(row["id"],"grokbot")
            self.assertTrue(grok.claim_message(row["id"],"grokbot","claim-run-0001")["claimed"])
            self.assertEqual(grok.acknowledge(row["id"],"grokbot","claim-run-0001")["status"],"acknowledged")
        finally: store.close()

    def test_public_origin_constraints(self):
        self.assertEqual(public_origin("https://bridge.example.com"),"https://bridge.example.com")
        for origin in ("http://bridge.example.com","https://user:pass@bridge.example.com","https://bridge.example.com/",
                       "https://bridge.example.com?token=a","https://localhost","https://bridge.example.com:444"):
            with self.assertRaises(BridgeError): public_origin(origin)

class EventTests(unittest.TestCase):
    def setUp(self):
        self.store=Store(":memory:")
        self.transport=FakeTransport()
        self.service=EventService(self.store,policy(),config(),self.transport)
    def tearDown(self): self.store.close()
    def subscribe(self, role="ada", **kwargs):
        params={"name":EVENT_NAME,"arguments":{"recipient":role},
                "delivery":{"mode":"webhook","url":"https://"+role.replace("grokbot","grok")+".example.com/callback","secret":KEY},
                "cursor":None}
        params.update(kwargs)
        return self.service.subscribe(role,params)
    def approved(self, recipient="ada", mid="wake-message-001"):
        row=self.store.stage("grokbot" if recipient=="ada" else "ada",recipient,"selected secret text",message_id=mid)["message"]
        self.assertEqual(self.store.wake_status()["notifications"],{})
        self.store.approve(row["id"])
        return row

    def test_verify_idempotent_subscribe_minimal_event_and_ack_separation(self):
        first=self.subscribe()
        self.assertEqual(first["id"],self.subscribe()["id"])
        self.assertEqual(len(self.transport.calls),1)
        row=self.approved()
        self.store.approve(row["id"])
        self.assertEqual(self.store.wake_status()["notifications"],{"pending":1})
        self.assertTrue(self.service.process_one())
        self.assertEqual(self.store.wake_status()["notifications"],{"accepted":1})
        self.assertEqual(self.store.inbox("ada")[0]["status"],"queued")
        packet=json.loads(self.transport.calls[-1][2])
        self.assertNotIn("text",packet["data"])
        self.assertNotIn(row["text"],self.transport.calls[-1][2].decode())
        self.assertEqual(packet["eventId"],self.transport.calls[-1][3]["webhook-id"])
        self.assertFalse(self.service.process_one())

    def test_invalid_subscriptions_and_verification_never_activate(self):
        self.transport.bad_challenge=True
        with self.assertRaises(EventError) as exc: self.subscribe()
        self.assertEqual(exc.exception.code,-32015)
        self.assertEqual(exc.exception.data["reason"],"challenge_failed")
        self.assertEqual(self.store.wake_status()["active_subscriptions"],0)
        with self.assertRaises(EventError): self.subscribe(arguments={"recipient":"grokbot"})
        with self.assertRaises(BridgeError): self.subscribe(delivery={"mode":"webhook","url":"http://ada.example.com/cb","secret":KEY})
        with self.assertRaises(BridgeError): self.subscribe(delivery={"mode":"webhook","url":"https://ada.example.com/cb","secret":"bad"})
        with self.assertRaises(EventError): self.subscribe(cursor="unsupported")
        self.assertEqual(self.store.wake_status()["active_subscriptions"],0)

    def test_secret_rotation_and_expiry(self):
        self.subscribe()
        newer="whsec_"+base64.b64encode(b"new public synthetic test fixture").decode()
        self.subscribe(delivery={"mode":"webhook","url":"https://ada.example.com/callback","secret":newer})
        self.approved()
        self.service.process_one()
        self.assertEqual(len(self.transport.calls[-1][3]["webhook-signature"].split()),2)
        with self.store.transaction(): self.store.db.execute("UPDATE subscriptions SET expires=0")
        row=self.store.stage("grokbot","ada","after expiry",message_id="expire-message-002")["message"]
        self.store.approve(row["id"])
        self.assertEqual(self.store.wake_status()["notifications"],{"accepted":1})

    def test_timeout_retries_same_event_bytes_and_fresh_signature(self):
        self.subscribe(); self.approved()
        self.transport.failure="timeout"
        self.service.process_one()
        row=dict(self.store.db.execute("SELECT * FROM outbox").fetchone())
        self.assertEqual(row["last_error"],"uncertain_timeout")
        self.assertEqual(row["status"],"pending")
        self.assertGreater(row["next_attempt"],time.time())
        self.assertFalse(self.service.process_one())
        self.transport.failure=None
        with self.store.transaction(): self.store.db.execute("UPDATE outbox SET next_attempt=0")
        self.service.process_one()
        self.assertEqual(self.transport.calls[-1][2],self.transport.calls[-2][2])
        self.assertEqual(self.store.wake_status()["notifications"],{"accepted":1})

    def test_permanent_rejection_and_attempt_limit(self):
        self.subscribe(); self.approved()
        self.transport.status=413
        self.service.process_one()
        self.assertEqual(self.store.wake_status()["notifications"],{"dead":1})
        self.assertFalse(self.service.process_one())
        with self.store.transaction(): self.store.db.execute("UPDATE outbox SET status='pending',attempts=7,next_attempt=0")
        self.transport.failure="timeout"
        self.service.process_one()
        self.assertEqual(self.store.db.execute("SELECT attempts FROM outbox").fetchone()[0],8)
        self.assertEqual(self.store.wake_status()["notifications"],{"dead":1})

    def test_410_stops_subscription(self):
        self.subscribe(); self.approved()
        self.transport.status=410
        self.service.process_one()
        self.assertEqual(self.store.wake_status()["active_subscriptions"],0)
        self.assertEqual(self.store.wake_status()["notifications"],{"dead":1})

    def test_unsubscribe_cancel_and_identity_isolation(self):
        self.subscribe(); self.approved()
        params={"name":EVENT_NAME,"arguments":{"recipient":"ada"},"delivery":{"mode":"webhook","url":"https://ada.example.com/callback"}}
        with self.assertRaises(EventError): self.service.unsubscribe("grokbot",params)
        self.service.unsubscribe("ada",params); self.service.unsubscribe("ada",params)
        self.assertEqual(self.store.wake_status()["notifications"],{"canceled":1})
        self.assertFalse(self.service.process_one())

    def test_cancel_ack_expired_or_revoked_message_skips_wake(self):
        self.subscribe(); row=self.approved()
        self.store.cancel(row["id"])
        self.assertFalse(self.service.process_one())
        row=self.store.stage("grokbot","ada","next",message_id="wake-message-002")["message"]
        self.store.approve(row["id"])
        self.service.policy.agents.pop("ada")
        count=len(self.transport.calls)
        self.service.process_one()
        self.assertEqual(len(self.transport.calls),count)
        self.assertIn("dead",self.store.wake_status()["notifications"])

    def test_restart_lease_recovery_and_backup(self):
        with tempfile.TemporaryDirectory(dir=ROOT,prefix=".test-cloud-") as folder:
            first=Store(Path(folder)/"bridge.sqlite3")
            service=EventService(first,policy(),config(),self.transport)
            params={"name":EVENT_NAME,"arguments":{"recipient":"ada"},"delivery":{"mode":"webhook","url":"https://ada.example.com/cb","secret":KEY}}
            service.subscribe("ada",params)
            row=first.stage("grokbot","ada","durable",message_id="restart-wake-001")["message"]
            first.approve(row["id"])
            claimed=service.claim()
            first.db.execute("UPDATE outbox SET lease_until=0"); first.db.commit()
            backup=first.backup(); first.close()
            second=Store(Path(folder)/"bridge.sqlite3")
            try:
                service=EventService(second,policy(),config(),self.transport)
                service.process_one()
                sent=json.loads(self.transport.calls[-1][2])
                self.assertEqual(sent["eventId"],claimed["event_id"])
                self.assertEqual(second.wake_status()["notifications"],{"accepted":1})
                copied=Store(Path(folder)/"backups"/backup)
                try: self.assertEqual(copied.wake_status()["notifications"],{"leased":1})
                finally: copied.close()
            finally: second.close()

    def test_two_connections_only_one_notification_lease(self):
        with tempfile.TemporaryDirectory(dir=ROOT,prefix=".test-race-") as folder:
            path=Path(folder)/"bridge.sqlite3"
            stores=[Store(path),Store(path)]
            services=[EventService(s,policy(),config(),self.transport) for s in stores]
            params={"name":EVENT_NAME,"arguments":{"recipient":"ada"},"delivery":{"mode":"webhook","url":"https://ada.example.com/cb","secret":KEY}}
            services[0].subscribe("ada",params)
            row=stores[0].stage("grokbot","ada","race",message_id="claim-race-wake-001")["message"];stores[0].approve(row["id"])
            results=[]
            threads=[threading.Thread(target=lambda svc=svc:results.append(svc.claim())) for svc in services]
            for t in threads:t.start()
            for t in threads:t.join()
            self.assertEqual(sum(r is not None for r in results),1)
            for s in stores:s.close()

    def test_claim_dedup_expiry_fencing_and_idempotent_receipt(self):
        row=self.store.stage("ada","grokbot","claimed",message_id="claimed-message-001")["message"]
        with self.assertRaises(BridgeError): self.store.claim_message(row["id"],"grokbot","workflow-001")
        self.store.approve(row["id"])
        self.assertTrue(self.store.claim_message(row["id"],"grokbot","workflow-001")["claimed"])
        self.assertFalse(self.store.claim_message(row["id"],"grokbot","workflow-002")["claimed"])
        with self.store.transaction(): self.store.db.execute("UPDATE message_claims SET expires=0")
        self.assertTrue(self.store.claim_message(row["id"],"grokbot","workflow-002")["claimed"])
        with self.assertRaises(BridgeError):self.store.acknowledge_claim(row["id"],"grokbot","workflow-001")
        self.store.acknowledge_claim(row["id"],"grokbot","workflow-002")
        self.store.acknowledge_claim(row["id"],"grokbot","workflow-002")
        self.assertFalse(self.store.claim_message(row["id"],"grokbot","workflow-003")["claimed"])

    def test_grok_supplied_contract_and_uncertain_retry(self):
        cfg=config(True)
        service=EventService(self.store,policy(),cfg,self.transport)
        row=self.approved("grokbot")
        service.process_one()
        role,url,body,headers=self.transport.calls[-1]
        self.assertEqual(json.loads(body),{"message_id":row["id"],"event":"bridge.message_ready","to":"grokbot","from":"ada"})
        self.assertEqual(headers,{"Authorization":"Bearer "+GROK,"Content-Type":"application/json"})
        self.assertNotIn("X-Automation-Key",headers)
        self.assertEqual(self.store.inbox("grokbot")[0]["status"],"queued")
        self.assertEqual(self.store.wake_status()["notifications"],{"accepted":1})
        self.transport.status=202
        status,_=GrokWebhookAdapter(cfg,self.transport).send(body)
        self.assertEqual(status,202)  # Caller must accept 200 only.

class TransportTests(unittest.TestCase):
    def test_standard_webhooks_independent_signature_vector(self):
        body=b'{"data":{"message_id":"example-message"}}'
        headers=signed_headers(KEY,"evt_public_fixture",body,"sub_public_fixture",signed_at=1234)
        expected=base64.b64encode(hmac.new(base64.b64decode(KEY[6:]),b"evt_public_fixture.1234."+body,hashlib.sha256).digest()).decode()
        self.assertEqual(headers["webhook-signature"],"v1,"+expected)
        for key in ("bad","whsec_"+base64.b64encode(b"short").decode(),"whsec_!"):
            with self.assertRaises(BridgeError):key_bytes(key)

    def test_ssrf_private_mixed_and_rebinding(self):
        def addresses(ip):return [(socket.AF_INET,socket.SOCK_STREAM,6,"",(ip,443))]
        for ip in ("127.0.0.1","169.254.169.254","10.0.0.1","192.168.1.1","0.0.0.0","224.0.0.1"):
            with patch("babel.wake.socket.getaddrinfo",return_value=addresses(ip)):
                with self.assertRaises(CallbackError):public_addresses("ada.example.com")
        with patch("babel.wake.socket.getaddrinfo",side_effect=[addresses("8.8.8.8"),addresses("127.0.0.1")]):
            self.assertEqual(public_addresses("ada.example.com")[0][-1][0],"8.8.8.8")
            with self.assertRaises(CallbackError):public_addresses("ada.example.com")
        with patch("babel.wake.socket.getaddrinfo",return_value=addresses("8.8.8.8")+addresses("10.0.0.1")):
            with self.assertRaises(CallbackError):public_addresses("ada.example.com")

    def test_destination_allowlist_query_credentials_redirect_policy(self):
        c=config()
        self.assertEqual(c.destination("ada","https://ada.example.com/cb").hostname,"ada.example.com")
        for url in ("http://ada.example.com/cb","https://ada.example.com:8443/cb","https://ada.example.com/cb?key=x",
                    "https://u:p@ada.example.com/cb","https://evil.example.com/cb","https://grok.example.com/cb"):
            with self.assertRaises(BridgeError):c.destination("ada",url)
        with self.assertRaises(BridgeError):WakeConfig().destination("ada","https://ada.example.com/cb")

class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store=Store(":memory:")
        cls.server=Gateway(0,policy(),"https://bridge.example.com",cls.store,transport=FakeTransport())
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base="http://127.0.0.1:"+str(cls.server.port)
        cls.opener=build_opener(ProxyHandler({}))
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.store.close()
    def request(self,path="/mcp",body=None,headers=None,method=None):
        hdr={"Host":"bridge.example.com","X-Forwarded-Proto":"https","Authorization":"Bearer "+ADA,
             "Content-Type":"application/json","Accept":"application/json, text/event-stream"}
        hdr.update(headers or {})
        req=Request(self.base+path,data=None if body is None else json.dumps(body).encode(),headers=hdr,method=method)
        try:response=self.opener.open(req,timeout=3)
        except HTTPError as exc:response=exc
        with response:return response.status,response.read(),dict(response.headers)
    def modern(self,method,params=None,headers=None):
        meta={"io.modelcontextprotocol/protocolVersion":mcp2.VERSION,"io.modelcontextprotocol/clientCapabilities":{}}
        params={**(params or {}),"_meta":meta}
        hdr={"MCP-Protocol-Version":mcp2.VERSION,"Mcp-Method":method}
        if "name" in params:hdr["Mcp-Name"]=params["name"]
        hdr.update(headers or {})
        return self.request(body={"jsonrpc":"2.0","id":1,"method":method,"params":params},headers=hdr)
    def test_unauthenticated_and_agent_routes_cannot_reach_admin(self):
        for path in ("/","/app.js","/api/session","/api/history","/api/approve","/mcp/ada","/mcp?key=secret"):
            self.assertEqual(self.request(path,{},headers={"Authorization":""})[0],401)
            self.assertEqual(self.request(path,{})[0],404)
        status,_,headers=self.request(body={},headers={"Authorization":"Bearer wrong"})
        self.assertEqual(status,401);self.assertIn("WWW-Authenticate",headers)
        self.assertEqual(self.request(body={},headers={"X-Forwarded-Proto":"http"})[0],403)
        self.assertEqual(self.request(body={},headers={"Origin":"https://evil.example.com"})[0],403)
        self.assertEqual(self.request(body={},headers={"Host":"evil.example.com"})[0],403)
    def test_modern_discovery_methods_metadata_and_header_validation(self):
        status,body,_=self.modern("server/discover")
        self.assertEqual(status,200)
        result=json.loads(body)["result"]
        self.assertEqual(result["supportedVersions"],[mcp2.VERSION])
        self.assertIn("events",result["capabilities"]);self.assertEqual(result["resultType"],"complete")
        self.assertEqual(self.modern("initialize")[0],404)
        self.assertEqual(self.modern("events/list")[0],200)
        status,body,_=self.modern("tools/list",headers={"Mcp-Method":"tools/call"})
        self.assertEqual(status,400);self.assertEqual(json.loads(body)["error"]["code"],-32020)
        status,body,_=self.modern("ping",headers={"MCP-Protocol-Version":"2025-11-25"})
        self.assertEqual(status,400);self.assertEqual(json.loads(body)["error"]["code"],-32020)
        self.assertEqual(self.request(body={"jsonrpc":"2.0","id":1,"method":"ping"})[0],400)
        self.assertEqual(self.request(method="DELETE")[0],405)
    def test_legacy_public_role_binding_and_claim_gate(self):
        rpc={"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stage_message","arguments":{
            "recipient":"grokbot","text":"public draft","message_id":"public-gateway-001"}}}
        status,body,_=self.request("/mcp/v1",rpc)
        self.assertEqual(status,200)
        row=json.loads(json.loads(body)["result"]["content"][0]["text"])["message"]
        self.assertEqual(row["source"],"ada");self.assertEqual(row["status"],"draft")
        rpc["params"]["arguments"]["source"]="grokbot"
        self.assertTrue(json.loads(self.request("/mcp/v1",rpc)[1])["result"]["isError"])
        self.assertEqual(self.store.inbox("grokbot"),[])
    def test_modern_header_encoded_name_and_unsupported_version(self):
        status,body,_=self.modern("tools/call",{"name":"receive_messages","arguments":{}},
                                {"Mcp-Name":"=?base64?"+base64.b64encode(b"receive_messages").decode()+"?="})
        self.assertEqual(status,200);self.assertFalse(json.loads(body)["result"]["isError"])
        request={"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"1900-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}
        status,body,_=self.request(body=request,headers={"MCP-Protocol-Version":"1900-01-01","Mcp-Method":"ping"})
        self.assertEqual(status,400);self.assertEqual(json.loads(body)["error"]["code"],-32022)

    def test_duplicate_framing_headers_are_rejected(self):
        payload=("POST /mcp/v1 HTTP/1.1\r\nHost: bridge.example.com\r\n"
                 "X-Forwarded-Proto: https\r\nAuthorization: Bearer "+ADA+"\r\n"
                 "Accept: application/json, text/event-stream\r\nContent-Type: application/json\r\n"
                 "Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}")
        with socket.create_connection(("127.0.0.1",self.server.port),timeout=3) as sock:
            sock.sendall(payload.encode())
            response=HTTPResponse(sock);response.begin()
            self.assertEqual(response.status,411);response.read();response.close()
