"""Public synthetic participants only; no real invitations or client connections."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler
from babel.auth import Policy, ScopedStore
from babel.core import Store, ROOT, BridgeError
from babel.enrollment import change, edit
from babel.events import EventService, EventError, EVENT_NAME
from babel.gateway import Gateway
from babel.mcp import dispatch
from babel.wake import WakeConfig
from tests.test_cloud import FakeTransport, KEY

DOT="owner_a.dots.dot_01"
CODEX="owner_a.codex.run_01"
SECOND="owner_a.codex.run_02"
GUEST="owner_b.cursor.run_01"
GROK="owner_b.grokbot.routine_01"
TOKENS={pid:"public-synthetic-credential-"+str(n).zfill(12) for n,pid in enumerate((DOT,CODEX,SECOND,GUEST,GROK))}
def fixture():
    now=int(time.time())
    participants={}
    for pid,token in TOKENS.items():
        owner,client,session=pid.split(".")
        participants[pid]={"owner":owner,"client":client,"session":session,"state":"active","accepted":True,
                           "activated_at":now-60,"expires":now+3600,"sha256":hashlib.sha256(token.encode()).hexdigest()}
    def conversation(a,b):
        return {"state":"active","participants":[a,b],"routes":[{"sender":a,"recipient":b},{"sender":b,"recipient":a}]}
    return {"schema_version":3,"owners":{"owner_a":{"enabled":True},"owner_b":{"enabled":True}},
            "participants":participants,"conversations":{
                "chat_shared_01":conversation(DOT,GUEST),
                "chat_private_01":conversation(CODEX,GROK),
                "chat_second_01":conversation(SECOND,GUEST)}}
def wake():
    return WakeConfig({"enabled":True,"callback_hosts":{DOT:["dot.example.com"],GUEST:["guest.example.com"]}})

class ParticipantTests(unittest.TestCase):
    def setUp(self):
        self.cfg=fixture();self.policy=Policy(self.cfg);self.store=Store(":memory:")
        self.store.policy_provider=lambda:self.policy
        self.store.sync_policy(self.policy)
    def tearDown(self):self.store.close()
    def scoped(self,role,policy=None):
        p=policy or self.policy
        return ScopedStore(self.store,role,p.agents[role][1],p)
    def stage(self,source=DOT,recipient=GUEST,cid="chat_shared_01",mid="participant-message-01",approved=True):
        row=self.scoped(source).stage(source,recipient,text="selected synthetic content",message_id=mid,conversation_id=cid)["message"]
        if approved: row=self.store.approve(row["id"])
        return row
    def replace_policy(self,cfg):
        self.policy=Policy(cfg);self.store.sync_policy(self.policy)
    def test_separate_mailboxes_history_owner_and_session(self):
        row=self.stage()
        self.assertEqual(row["source_owner"],"owner_a");self.assertEqual(row["recipient_owner"],"owner_b")
        self.assertEqual(self.scoped(GUEST).inbox(GUEST)[0]["id"],row["id"])
        for role in (CODEX,SECOND,GROK):
            self.assertEqual(self.scoped(role).history(role),[])
            self.assertEqual(self.scoped(role).inbox(role),[])
            with self.assertRaises(BridgeError) as exc:self.scoped(role).message_status(row["id"],role)
            self.assertEqual(exc.exception.status,404)
            with self.assertRaises(BridgeError):self.scoped(role).claim_message(row["id"],role,"synthetic-claim-01")
    def test_same_owner_and_client_sessions_do_not_share_history(self):
        row=self.stage(CODEX,GROK,"chat_private_01","same-client-session-001")
        self.assertEqual(self.scoped(SECOND).history(SECOND),[])
        with self.assertRaises(BridgeError):self.scoped(SECOND).message_status(row["id"],SECOND)
        with self.assertRaises(BridgeError):self.scoped(SECOND).claim_message(row["id"],SECOND,"wrong-session-claim")

    def test_identity_is_bound_not_a_caller_label(self):
        for source,recipient,cid in ((GUEST,DOT,"chat_shared_01"),(DOT,GROK,"chat_private_01"),(DOT,GUEST,None)):
            with self.assertRaises(BridgeError):
                self.scoped(DOT).stage(source,recipient,text="spoof",message_id="spoof-message-001",conversation_id=cid)
        rpc={"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stage_message","arguments":{
            "source":GUEST,"recipient":GUEST,"text":"spoof","message_id":"spoof-message-002","conversation_id":"chat_shared_01"}}}
        self.assertTrue(dispatch(self.scoped(DOT),DOT,rpc)["result"]["isError"])
    def test_membership_without_direction_grant_is_not_permission(self):
        cfg=copy.deepcopy(self.cfg);cfg["conversations"]["chat_shared_01"]["routes"]=[{"sender":DOT,"recipient":GUEST}]
        self.replace_policy(cfg)
        row=self.stage()
        with self.assertRaises(BridgeError):
            self.scoped(GUEST).stage(GUEST,DOT,text="ungranted reply",message_id="reply-message-001",reply_to=row["id"],conversation_id="chat_shared_01")
        cfg=copy.deepcopy(cfg);cfg["conversations"]["chat_shared_01"]["routes"]=[]
        self.replace_policy(cfg)
        self.assertEqual(self.scoped(GUEST).history(GUEST),[])
    def test_foreign_reply_and_conversation_hop_are_denied(self):
        row=self.stage()
        with self.assertRaises(BridgeError):
            self.scoped(GROK).stage(GROK,CODEX,text="foreign parent",message_id="reply-message-002",reply_to=row["id"],conversation_id="chat_private_01")
        cfg=copy.deepcopy(self.cfg);cfg["conversations"]["chat_alternate_01"]=copy.deepcopy(cfg["conversations"]["chat_shared_01"])
        self.replace_policy(cfg)
        with self.assertRaises(BridgeError):
            self.scoped(GUEST).stage(GUEST,DOT,text="other conversation",message_id="reply-message-003",reply_to=row["id"],conversation_id="chat_alternate_01")
    def test_grant_removal_hides_old_data_and_fences_claim_and_receipt(self):
        row=self.stage()
        guest=self.scoped(GUEST)
        self.assertTrue(guest.claim_message(row["id"],GUEST,"synthetic-claim-01")["claimed"])
        cfg=copy.deepcopy(self.cfg);cfg["conversations"]["chat_shared_01"]["routes"]=[]
        self.replace_policy(cfg);guest=self.scoped(GUEST)
        self.assertEqual(guest.history(GUEST),[]);self.assertEqual(guest.inbox(GUEST),[])
        for action in (lambda:guest.claim_message(row["id"],GUEST,"synthetic-claim-01"),
                       lambda:guest.acknowledge(row["id"],GUEST,"synthetic-claim-01"),
                       lambda:self.scoped(DOT).message_status(row["id"],DOT)):
            with self.assertRaises(BridgeError):action()
        self.assertEqual(self.store.history()[0]["id"],row["id"])
    def test_revoked_invited_closed_and_disabled_owner_cannot_authenticate(self):
        for state in ("invited","closed","revoked"):
            cfg=copy.deepcopy(self.cfg);entry=cfg["participants"][GUEST];entry["state"]=state
            if state=="invited":entry["accepted"]=False
            p=Policy(cfg)
            with self.assertRaises(BridgeError):p.authenticate("Bearer "+TOKENS[GUEST])
        cfg=copy.deepcopy(self.cfg);cfg["owners"]["owner_b"]["enabled"]=False
        with self.assertRaises(BridgeError):Policy(cfg).authenticate("Bearer "+TOKENS[GUEST])
    def test_close_is_permanent_and_identity_cannot_be_recycled(self):
        self.stage()
        cfg=copy.deepcopy(self.cfg);cfg["participants"][GUEST]["state"]="closed";self.replace_policy(cfg)
        self.store.sync_policy(self.policy) # stable closed config remains usable
        with self.assertRaises(BridgeError):self.replace_policy(self.cfg)
        cfg["participants"].pop(GUEST)
        cfg["conversations"].pop("chat_shared_01");cfg["conversations"].pop("chat_second_01")
        self.replace_policy(cfg)
        with self.assertRaises(BridgeError):self.replace_policy(self.cfg)
    def test_expiry_creates_tombstone_and_cannot_be_extended_to_reopen(self):
        cfg=copy.deepcopy(self.cfg);cfg["participants"][GUEST]["expires"]=int(time.time())-1
        self.replace_policy(cfg)
        with self.assertRaises(BridgeError):self.policy.authenticate("Bearer "+TOKENS[GUEST])
        with self.assertRaises(BridgeError):self.replace_policy(self.cfg)
    def test_persistent_participants_stay_connected_and_still_revoke(self):
        from unittest.mock import patch
        cfg=copy.deepcopy(self.cfg)
        for entry in cfg["participants"].values(): entry["expires"]=None
        self.replace_policy(cfg)
        with patch("time.time",return_value=time.time()+10*365*86400):
            self.store.sync_policy(self.policy)
            self.assertEqual(self.policy.authenticate("Bearer "+TOKENS[DOT]),DOT)
            self.assertEqual(self.scoped(DOT).contacts(DOT),[{"recipient":GUEST,"conversation_id":"chat_shared_01"}])
        cfg["participants"][GUEST]["state"]="revoked";self.replace_policy(cfg)
        with self.assertRaises(BridgeError):self.policy.authenticate("Bearer "+TOKENS[GUEST])
        cfg["participants"][GUEST]["state"]="active"
        with self.assertRaises(BridgeError):self.replace_policy(cfg)

    def test_persistent_recipient_wake_renews_beyond_old_participant_limit(self):
        from unittest.mock import patch
        cfg=copy.deepcopy(self.cfg)
        for entry in cfg["participants"].values(): entry["expires"]=None
        self.replace_policy(cfg)
        transport=FakeTransport()
        params={"name":EVENT_NAME,"arguments":{"recipient":GUEST},
                "delivery":{"mode":"webhook","url":"https://guest.example.com/callback","secret":KEY}}
        service=EventService(self.store,self.policy,wake(),transport)
        first=service.subscribe(GUEST,params)
        future=time.time()+40*86400
        with patch("time.time",return_value=future):
            renewed=service.subscribe(GUEST,params)
            self.assertEqual(first["id"],renewed["id"])
            row=self.stage(mid="persistent-future-wake-001")
            self.assertTrue(service.process_one())
            self.assertEqual(self.store.db.execute("SELECT status FROM outbox WHERE message_id=?",(row["id"],)).fetchone()[0],"accepted")
    def test_credential_rotation_rejects_old_and_reused_credentials(self):
        cfg=copy.deepcopy(self.cfg)
        fresh="public-synthetic-rotated-credential-000000"
        cfg["participants"][GUEST]["sha256"]=hashlib.sha256(fresh.encode()).hexdigest()
        self.replace_policy(cfg)
        self.assertEqual(self.policy.authenticate("Bearer "+fresh),GUEST)
        with self.assertRaises(BridgeError):self.policy.authenticate("Bearer "+TOKENS[GUEST])
        with self.assertRaises(BridgeError):self.replace_policy(self.cfg)
        cfg2=copy.deepcopy(cfg);cfg2["participants"][SECOND]["sha256"]=hashlib.sha256(TOKENS[GUEST].encode()).hexdigest()
        with self.assertRaises(BridgeError):self.replace_policy(cfg2)
    def test_owner_rate_budget_is_not_bypassed_by_more_sessions(self):
        for n in range(10):
            self.stage(source=CODEX,recipient=GROK,cid="chat_private_01",mid="owner-rate-message-"+str(n),approved=False)
        with self.assertRaises(BridgeError) as exc:
            self.stage(source=SECOND,recipient=GUEST,cid="chat_second_01",mid="owner-rate-message-extra",approved=False)
        self.assertEqual(exc.exception.status,429)
    def test_tool_catalog_exposes_only_own_routes_and_no_admin_tools(self):
        tools=dispatch(self.scoped(DOT),DOT,{"jsonrpc":"2.0","id":1,"method":"tools/list"})["result"]["tools"]
        stage=tools[0]["inputSchema"]
        self.assertNotIn("enum",stage["properties"]["recipient"])
        self.assertNotIn("enum",stage["properties"]["conversation_id"])
        self.assertEqual(self.scoped(DOT).contacts(DOT),[{"recipient":GUEST,"conversation_id":"chat_shared_01"}])
        self.assertIn("conversation_id",stage["required"])
        self.assertNotIn("policy",str(tools));self.assertNotIn(CODEX,str(tools))
        for name in ("approve_message","enroll_participant","run_command"):
            result=dispatch(self.scoped(GUEST),GUEST,{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":{}}})
            self.assertTrue(result["result"]["isError"])
    def test_contact_discovery_updates_without_stale_cached_recipient_enums(self):
        cfg=copy.deepcopy(self.cfg)
        with tempfile.TemporaryDirectory(dir=ROOT,prefix=".test-") as folder:
            path=Path(folder)/"participants.json";path.write_text(json.dumps(cfg))
            original=Policy.load(path)
            scope=ScopedStore(self.store,DOT,original.agents[DOT][1],original)
            catalog=dispatch(scope,DOT,{"jsonrpc":"2.0","id":1,"method":"tools/list"})["result"]["tools"]
            self.assertNotIn("enum",catalog[0]["inputSchema"]["properties"]["recipient"])
            cfg["conversations"]["dynamic_chat_01"]={"state":"active","participants":[DOT,CODEX],"routes":[{"sender":DOT,"recipient":CODEX}]}
            path.write_text(json.dumps(cfg))
            fresh=Policy.load(path);fresh_scope=ScopedStore(self.store,DOT,fresh.agents[DOT][1],fresh)
            rpc={"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_contacts","arguments":{}}}
            contacts=json.loads(dispatch(fresh_scope,DOT,rpc)["result"]["content"][0]["text"])["contacts"]
            self.assertIn({"recipient":CODEX,"conversation_id":"dynamic_chat_01"},contacts)
            self.assertNotIn(SECOND,str(contacts))
            cfg["participants"][CODEX]["state"]="closed";path.write_text(json.dumps(cfg))
            fresh=Policy.load(path)
            contacts=ScopedStore(self.store,DOT,fresh.agents[DOT][1],fresh).contacts(DOT)
            self.assertNotIn(CODEX,str(contacts))
    def test_approval_uses_current_policy_not_staged_permissions(self):
        row=self.stage(approved=False)
        cfg=copy.deepcopy(self.cfg);cfg["conversations"]["chat_shared_01"]["state"]="closed"
        self.replace_policy(cfg)
        with self.assertRaises(BridgeError):self.store.approve(row["id"])
        self.assertEqual(self.store.history()[0]["status"],"draft")
    def test_subscriptions_and_pending_wakes_are_recipient_scoped_and_revocable(self):
        transport=FakeTransport();service=EventService(self.store,self.policy,wake(),transport)
        params={"name":EVENT_NAME,"arguments":{"recipient":GUEST},"delivery":{"mode":"webhook","url":"https://guest.example.com/callback","secret":KEY}}
        service.subscribe(GUEST,params)
        with self.assertRaises(EventError):service.subscribe(DOT,params)
        row=self.stage();self.assertEqual(self.store.wake_status()["notifications"]["pending"],1)
        cfg=copy.deepcopy(self.cfg);cfg["conversations"]["chat_shared_01"]["routes"]=[]
        self.replace_policy(cfg)
        after=EventService(self.store,self.policy,wake(),transport)
        self.assertFalse(after.process_one());self.assertEqual(len(transport.calls),1)
        self.assertEqual(self.store.wake_status()["notifications"]["canceled"],1)
    def test_grok_410_is_not_automatically_rearmed_by_worker_restart(self):
        cfg=WakeConfig({"enabled":True,"callback_hosts":{GROK:["grok.example.com"]},
            "grok_routines":{GROK:{"enabled":True,"url":"https://grok.example.com/routine","sender_key":"public-synthetic-sender-key-00000"}}})
        transport=FakeTransport();transport.status=410
        service=EventService(self.store,self.policy,cfg,transport)
        self.stage(CODEX,GROK,"chat_private_01","gone-grok-message-001")
        service.process_one();self.assertEqual(len(transport.calls),1)
        restarted=EventService(self.store,self.policy,cfg,transport)
        self.stage(CODEX,GROK,"chat_private_01","gone-grok-message-002")
        self.assertFalse(restarted.process_one());self.assertEqual(len(transport.calls),1)
        self.assertEqual(self.store.wake_status()["active_subscriptions"],0)

    def test_two_owners_grok_wakes_use_their_own_routine_and_sender_key(self):
        other="owner_a.grokbot.routine_01"
        cfg=copy.deepcopy(self.cfg);now=int(time.time())
        cfg["participants"][other]={"owner":"owner_a","client":"grokbot","session":"routine_01","state":"active","accepted":True,
            "activated_at":now-60,"expires":now+3600,"sha256":hashlib.sha256(b"public-synthetic-other-grok-credential").hexdigest()}
        cfg["conversations"]["two-grok-chat-01"]={"state":"active","participants":[other,GROK],"routes":[{"sender":other,"recipient":GROK},{"sender":GROK,"recipient":other}]}
        self.replace_policy(cfg)
        wake_cfg=WakeConfig({"enabled":True,"callback_hosts":{other:["one.example.com"],GROK:["two.example.com"]},
            "grok_routines":{other:{"enabled":True,"url":"https://one.example.com/routine","sender_key":"public-synthetic-one-sender-key"},
                             GROK:{"enabled":True,"url":"https://two.example.com/routine","sender_key":"public-synthetic-two-sender-key"}}})
        transport=FakeTransport();service=EventService(self.store,self.policy,wake_cfg,transport)
        self.stage(other,GROK,"two-grok-chat-01","two-grok-message-001")
        self.stage(GROK,other,"two-grok-chat-01","two-grok-message-002")
        self.assertTrue(service.process_one());self.assertTrue(service.process_one())
        self.assertEqual([call[1] for call in transport.calls],["https://two.example.com/routine","https://one.example.com/routine"])
        self.assertEqual([call[3]["Authorization"] for call in transport.calls],["Bearer public-synthetic-two-sender-key","Bearer public-synthetic-one-sender-key"])
        self.assertEqual([json.loads(call[2])["to"] for call in transport.calls],[GROK,other])

    def test_multiple_grok_destinations_use_distinct_participant_binding(self):
        cfg=WakeConfig({"enabled":True,"callback_hosts":{GROK:["grok.example.com"]},
                        "grok_routines":{GROK:{"enabled":True,"url":"https://grok.example.com/routine","sender_key":"public-synthetic-sender-key-00000"}}})
        transport=FakeTransport();service=EventService(self.store,self.policy,cfg,transport)
        row=self.stage(CODEX,GROK,"chat_private_01","grok-participant-message-001")
        self.assertTrue(service.process_one())
        role,url,body,headers=transport.calls[0]
        self.assertEqual(role,GROK);self.assertEqual(json.loads(body)["to"],GROK)
        self.assertIn("Authorization",headers);self.assertNotIn("X-Automation-Key",headers)
        self.assertEqual(self.store.message_status(row["id"],CODEX)["status"],"queued")

class EnrollmentTests(unittest.TestCase):
    def test_persistent_enrollment_is_default_and_can_convert_live_instances(self):
        from unittest.mock import patch
        for client in ("dots","grokbot","codex","cursor","claude","opencode"):
            cfg=change(fixture(),"invite",owner="owner_a",client=client,session="persistent_01")
            pid="owner_a."+client+".persistent_01"
            self.assertIsNone(cfg["participants"][pid]["expires"])
            cfg=change(cfg,"activate",participant=pid,accepted=True,
                       sha256=hashlib.sha256(("persistent-synthetic-"+client).encode()).hexdigest())
            with patch("time.time",return_value=time.time()+365*86400):Policy(cfg).assert_active(pid)
        original=fixture();cfg=change(original,"persistent",participant=DOT)
        self.assertIsNone(cfg["participants"][DOT]["expires"])
        self.assertEqual(cfg["participants"][DOT]["activated_at"],original["participants"][DOT]["activated_at"])

    def test_persistence_cannot_reopen_expired_closed_or_unaccepted_instances(self):
        for state in ("closed","revoked"):
            cfg=fixture();cfg["participants"][DOT]["state"]=state
            with self.assertRaises(BridgeError):change(cfg,"persistent",participant=DOT)
        cfg=fixture();cfg["participants"][DOT]["expires"]=int(time.time())-1
        with self.assertRaises(BridgeError):change(cfg,"persistent",participant=DOT)
        cfg=fixture();cfg["participants"][DOT].update(expires=None,accepted=False)
        with self.assertRaises(BridgeError):Policy(cfg)
        cfg=fixture();cfg["participants"][DOT]["expires"]=True
        with self.assertRaises(BridgeError):Policy(cfg)

    def test_claude_and_opencode_have_distinct_bounded_interactive_instances(self):
        from babel.core import agent
        for client in ("claude", "opencode"):
            with self.subTest(client=client):
                cfg=fixture(); now=int(time.time())
                cfg=change(cfg,"invite",owner="owner_a",client=client,session="task_01",expires=now+3600)
                pid="owner_a."+client+".task_01"
                self.assertEqual(agent(pid),pid)
                token="public-synthetic-"+client+"-instance-0000"
                cfg=change(cfg,"activate",participant=pid,accepted=True,sha256=hashlib.sha256(token.encode()).hexdigest())
                self.assertEqual(Policy(cfg).agents[pid][1],frozenset())
                with self.assertRaises(BridgeError):
                    change(fixture(),"invite",owner="owner_a",client=client,session="too_long",expires=now+86401)
                cfg["participants"][pid]["expires"]=cfg["participants"][pid]["activated_at"]+86401
                with self.assertRaises(BridgeError): Policy(cfg)

    def test_invitation_has_no_credential_or_permission_until_operator_activation(self):
        cfg=fixture()
        cfg=change(cfg,"invite",owner="owner_b",client="codex",session="new_run",expires=int(time.time())+1800)
        pid="owner_b.codex.new_run";entry=cfg["participants"][pid]
        self.assertEqual(entry["state"],"invited");self.assertFalse(entry["accepted"]);self.assertNotIn("sha256",entry)
        with self.assertRaises(BridgeError):change(cfg,"activate",participant=pid,accepted=False)
        digest=hashlib.sha256(b"public-synthetic-enrollment-key-0000").hexdigest()
        cfg=change(cfg,"activate",participant=pid,accepted=True,sha256=digest)
        self.assertEqual(Policy(cfg).agents[pid][1],frozenset())
        cfg=change(cfg,"conversation",conversation="new-chat-001",members=[pid,DOT])
        cfg=change(cfg,"grant",conversation="new-chat-001",sender=pid,recipient=DOT)
        self.assertIn(DOT,Policy(cfg).agents[pid][1])
        cfg=change(cfg,"revoke-owner",owner="owner_b")
        self.assertEqual(cfg["participants"][pid]["state"],"revoked")
    def test_atomic_private_file_edits_and_legacy_refusal(self):
        with tempfile.TemporaryDirectory(dir=ROOT,prefix=".test-") as folder:
            path=Path(folder)/"participants.json";path.write_text(json.dumps(fixture()));path.chmod(0o600)
            edit(path,"revoke",participant=GUEST)
            self.assertEqual(json.loads(path.read_text())["participants"][GUEST]["state"],"revoked")
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            link=Path(folder)/"link.json";link.symlink_to(path)
            with self.assertRaises(BridgeError):edit(link,"validate")
            path.write_text('{"schema_version":1,"agents":{}}')
            with self.assertRaises(BridgeError):edit(path,"owner",owner="owner_c")

class HotRevocationTests(unittest.TestCase):
    def test_gateway_reloads_revocation_without_restart_and_denies_private_admin(self):
        with tempfile.TemporaryDirectory(dir=ROOT,prefix=".test-") as folder:
            path=Path(folder)/"participants.json";cfg=fixture();path.write_text(json.dumps(cfg))
            store=Store(":memory:");server=Gateway(0,Policy.load(path),"https://bridge.example.com",store,transport=FakeTransport())
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            opener=build_opener(ProxyHandler({}))
            def call(pathname="/mcp/v1",token=None):
                req=Request("http://127.0.0.1:"+str(server.port)+pathname,data=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
                    headers={"Host":"bridge.example.com","X-Forwarded-Proto":"https",
                             "Authorization":"Bearer "+(token or TOKENS[GUEST]),
                             "Content-Type":"application/json","Accept":"application/json, text/event-stream"})
                try:response=opener.open(req,timeout=3)
                except HTTPError as exc:response=exc
                with response:return response.status,response.read()
            try:
                self.assertEqual(call()[0],200)
                for pathname in ("/api/history","/api/approve","/api/policy","/mcp/"+DOT):
                    self.assertEqual(call(pathname)[0],404)
                cfg["participants"][GUEST]["state"]="revoked";path.write_text(json.dumps(cfg))
                self.assertEqual(call()[0],403)
                self.assertEqual(call(token=TOKENS[DOT])[0],200)
                path.write_text("{}")
                self.assertNotEqual(call(token=TOKENS[DOT])[0],200)
            finally:server.shutdown();server.server_close();thread.join();store.close()

try:
    from tests import test_oauth as oauth_fixtures
    jwt=oauth_fixtures.jwt
    from babel.oauth import OAuthPolicy
except ImportError:
    jwt=None

@unittest.skipUnless(jwt,"Optional OAuth dependencies unavailable")
class ParticipantOAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        oauth_fixtures.OAuthTests.setUpClass()
    def setUp(self):
        self.cfg=fixture();self.cfg["participants"][DOT].pop("sha256")
        self.cfg["oauth"]={"issuer":"https://synthetic.example.com/","resource":"https://bridge.example.com/mcp",
            "jwks_file":"unused-public-fixture.json","principals":{DOT:{"subject":"synthetic-user","client_id":"synthetic-client"}}}
    def policy(self,cfg=None):
        return OAuthPolicy(cfg or self.cfg,{"keys":[oauth_fixtures.OAuthTests.jwk]})
    def token(self,**changes):
        now=int(time.time())
        claims={"iss":self.cfg["oauth"]["issuer"],"aud":self.cfg["oauth"]["resource"],"sub":"synthetic-user",
                "azp":"synthetic-client","scope":"babel","iat":now-1,"exp":now+299}
        claims.update(changes)
        return jwt.encode(claims,oauth_fixtures.OAuthTests.key,algorithm="RS256",headers={"kid":oauth_fixtures.OAuthTests.jwk["kid"]})
    def test_oauth_and_static_participants_bind_to_distinct_instances(self):
        p=self.policy()
        self.assertEqual(p.authenticate("Bearer "+self.token()),DOT)
        self.assertEqual(p.authenticate("Bearer "+TOKENS[GROK]),GROK)
        with self.assertRaises(BridgeError):p.authenticate("Bearer "+self.token(sub="other-owner"))
    def test_same_account_and_client_cannot_select_another_dot_label(self):
        cfg=copy.deepcopy(self.cfg)
        cfg["participants"][SECOND].pop("sha256")
        cfg["oauth"]["principals"][SECOND]=copy.deepcopy(cfg["oauth"]["principals"][DOT])
        with self.assertRaises(BridgeError):self.policy(cfg)
    def test_tokens_predating_instance_enrollment_are_rejected(self):
        with self.assertRaises(BridgeError) as exc:self.policy().authenticate("Bearer "+self.token(iat=int(time.time())-120))
        self.assertEqual(exc.exception.status,401)
        self.assertEqual(self.policy().authenticate("Bearer "+self.token()),DOT)
    def test_oauth_principals_cannot_recycle_to_another_instance_after_close(self):
        cfg=copy.deepcopy(self.cfg);new="owner_a.dots.dot_02";now=int(time.time())
        cfg["participants"][DOT]["state"]="closed"
        cfg["participants"][new]=copy.deepcopy(cfg["participants"][DOT])
        cfg["participants"][new].update(session="dot_02",state="active",activated_at=now-10,expires=now+3600)
        cfg["oauth"]["principals"]={new:cfg["oauth"]["principals"][DOT]}
        store=Store(":memory:")
        try:
            old=self.policy();store.sync_policy(old);store.policy_provider=lambda:old
            row=ScopedStore(store,DOT,old.agents[DOT][1],old).stage(DOT,GUEST,text="old dot content",message_id="oauth-instance-old-01",conversation_id="chat_shared_01")["message"]
            store.approve(row["id"])
            with self.assertRaises(BridgeError):store.sync_policy(self.policy(cfg))
            cfg["oauth"]["principals"][new]["client_id"]="distinct-approved-client"
            fresh=self.policy(cfg);store.sync_policy(fresh)
            scoped=ScopedStore(store,new,fresh.agents[new][1],fresh)
            self.assertEqual(scoped.history(new),[])
            with self.assertRaises(BridgeError):scoped.message_status(row["id"],new)
        finally:store.close()

class PersistenceAndRevocationTests(unittest.TestCase):
    def test_tombstones_survive_restart_and_legacy_history_stays_isolated(self):
        with tempfile.TemporaryDirectory(dir=ROOT,prefix=".test-") as folder:
            path=Path(folder)/"bridge.sqlite3";cfg=fixture()
            store=Store(path)
            store.stage("ada","grokbot","legacy synthetic",message_id="legacy-archive-0001")
            store.sync_policy(Policy(cfg))
            cfg["participants"][GUEST]["state"]="revoked";store.sync_policy(Policy(cfg));store.close()
            restarted=Store(path)
            try:
                restarted.sync_policy(Policy(cfg))
                with self.assertRaises(BridgeError):restarted.sync_policy(Policy(fixture()))
                p=Policy(cfg);scope=ScopedStore(restarted,DOT,p.agents[DOT][1],p)
                self.assertEqual(scope.history(DOT),[])
                self.assertEqual(restarted.history()[0]["text"],"legacy synthetic")
            finally:restarted.close()
    def test_sender_revocation_stops_a_retrying_wake(self):
        cfg=fixture();p=Policy(cfg);store=Store(":memory:");store.policy_provider=lambda:p
        transport=FakeTransport();service=EventService(store,p,wake(),transport)
        try:
            service.subscribe(GUEST,{"name":EVENT_NAME,"arguments":{"recipient":GUEST},
                "delivery":{"mode":"webhook","url":"https://guest.example.com/callback","secret":KEY}})
            row=ScopedStore(store,DOT,p.agents[DOT][1],p).stage(DOT,GUEST,text="synthetic retry",message_id="retry-revoked-001",conversation_id="chat_shared_01")["message"]
            store.approve(row["id"]);transport.failure="timeout";service.process_one()
            count=len(transport.calls)
            cfg["participants"][DOT]["state"]="revoked";p=Policy(cfg)
            next_service=EventService(store,p,wake(),transport)
            store.db.execute("UPDATE outbox SET next_attempt=0");store.db.commit()
            next_service.process_one()
            self.assertEqual(len(transport.calls),count)
            self.assertIn("dead",store.wake_status()["notifications"])
        finally:store.close()
    def test_stale_scoped_handle_cannot_read_after_identity_revocation(self):
        cfg=fixture();p=Policy(cfg);store=Store(":memory:")
        try:
            scope=ScopedStore(store,GUEST,p.agents[GUEST][1],p)
            cfg["participants"][GUEST]["state"]="revoked";store.sync_policy(Policy(cfg))
            with self.assertRaises(BridgeError):scope.history(GUEST)
            with self.assertRaises(BridgeError):scope.inbox(GUEST)
        finally:store.close()
    def test_callback_verification_rechecks_authority_before_activation(self):
        with tempfile.TemporaryDirectory(dir=ROOT,prefix=".test-") as folder:
            path=Path(folder)/"participants.json";cfg=fixture();path.write_text(json.dumps(cfg))
            store=Store(":memory:")
            class RevokeDuringVerification(FakeTransport):
                def post(self,*args):
                    cfg["participants"][GUEST]["state"]="revoked";path.write_text(json.dumps(cfg))
                    return super().post(*args)
            try:
                service=EventService(store,Policy.load(path),wake(),RevokeDuringVerification())
                with self.assertRaises(BridgeError):service.subscribe(GUEST,{"name":EVENT_NAME,"arguments":{"recipient":GUEST},
                    "delivery":{"mode":"webhook","url":"https://guest.example.com/callback","secret":KEY}})
                self.assertEqual(store.wake_status()["active_subscriptions"],0)
            finally:store.close()

class OperatorParticipantUITests(unittest.TestCase):
    def test_private_console_uses_participants_and_current_approval_policy(self):
        from unittest.mock import patch
        from babel.server import Server
        with tempfile.TemporaryDirectory(dir=ROOT,prefix=".test-") as folder:
            path=Path(folder)/"participants.json";cfg=fixture();path.write_text(json.dumps(cfg))
            store=Store(":memory:")
            with patch.dict("os.environ",{"BABEL_AUTH_FILE":str(path)}):
                server=Server(0,store)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            opener=build_opener(ProxyHandler({}));base="http://127.0.0.1:"+str(server.port)
            def call(route,body=None,csrf=None):
                headers={"Content-Type":"application/json"}
                if csrf:headers["X-Babel-CSRF"]=csrf
                req=Request(base+route,data=None if body is None else json.dumps(body).encode(),headers=headers)
                try:response=opener.open(req,timeout=3)
                except HTTPError as exc:response=exc
                with response:return response.status,json.loads(response.read())
            try:
                status,session=call("/api/session")
                self.assertEqual(status,200);self.assertIn(GUEST,session["agents"]);self.assertIn("chat_shared_01",session["conversations"])
                status,row=call("/api/stage",{"source":DOT,"recipient":GUEST,"text":"synthetic operator draft",
                    "message_id":"operator-participant-01","conversation_id":"chat_shared_01"},session["csrf"])
                self.assertEqual(status,200);self.assertEqual(row["message"]["status"],"draft")
                self.assertEqual(call("/mcp/ada",{"jsonrpc":"2.0","id":1,"method":"tools/list"})[0],403)
                cfg["conversations"]["chat_shared_01"]["routes"]=[];path.write_text(json.dumps(cfg))
                self.assertEqual(call("/api/approve",{"message_id":"operator-participant-01"},session["csrf"])[0],403)
            finally:server.shutdown();server.server_close();thread.join();store.close()

class EnrollmentCLITests(unittest.TestCase):
    def test_cli_invite_and_activation_flag_never_issue_credentials(self):
        import subprocess,sys
        with tempfile.TemporaryDirectory(dir=ROOT,prefix=".test-") as folder:
            path=Path(folder)/"participants.json";path.write_text(json.dumps(fixture()))
            command=[sys.executable,"-m","babel","policy","--file",str(path)]
            result=subprocess.run(command+["invite","--owner","owner_b","--client","codex","--session","cli_01",
                "--expires",str(int(time.time())+1800)],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn("no credentials issued",result.stdout)
            entry=json.loads(path.read_text())["participants"]["owner_b.codex.cli_01"]
            self.assertEqual(entry["state"],"invited");self.assertNotIn("sha256",entry)
            result=subprocess.run(command+["activate","--participant","owner_b.codex.cli_01"],cwd=ROOT,capture_output=True,text=True)
            self.assertEqual(result.returncode,2)
            self.assertEqual(json.loads(path.read_text())["participants"]["owner_b.codex.cli_01"]["state"],"invited")
