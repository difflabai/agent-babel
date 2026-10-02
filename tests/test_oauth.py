"""Synthetic OAuth fixtures: keys exist in memory only; no provider is contacted."""
import copy
import hashlib
import json
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener
from babel.core import Store, BridgeError
from babel.gateway import Gateway
from babel.oauth import OAuthPolicy
from babel import mcp2
from babel.wake import PinnedHTTPS, WebhookTransport, CallbackError
from tests.test_cloud import GROK, FakeTransport, config

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    jwt = None

@unittest.skipUnless(jwt, "Optional OAuth verification dependencies are not installed")
class OAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        cls.jwk.update(kid="synthetic-memory-key", alg="RS256", use="sig")
        cls.cfg = {"schema_version":2,"agents":{
            "ada":{"recipients":["grokbot"]},
            "grokbot":{"sha256":hashlib.sha256(GROK.encode()).hexdigest(),"recipients":["ada"]}},
            "oauth":{"issuer":"https://synthetic.example.com/","resource":"https://bridge.example.com/mcp",
                     "jwks_file":"unused-public-fixture.json",
                     "principals":{"ada":{"subject":"synthetic-user","client_id":"synthetic-client"}}}}
    def policy(self, cfg=None, jwks=None):
        return OAuthPolicy(cfg or self.cfg, jwks or {"keys":[self.jwk]})
    def token(self, changes=None, headers=None, key=None, algorithm="RS256"):
        now=int(time.time())
        claims={"iss":self.cfg["oauth"]["issuer"],"aud":self.cfg["oauth"]["resource"],
                "sub":"synthetic-user","azp":"synthetic-client","scope":"babel",
                "iat":now-1,"exp":now+299}
        claims.update(changes or {})
        return jwt.encode(claims,key or self.key,algorithm=algorithm,
                          headers={"kid":self.jwk["kid"],**(headers or {})})
    def rejected(self, token, status=401):
        with self.assertRaises(BridgeError) as exc:
            self.policy().authenticate("Bearer "+token)
        self.assertEqual(exc.exception.status,status)
    def test_valid_scope_role_and_static_compatibility(self):
        p=self.policy()
        self.assertEqual(p.authenticate("Bearer "+self.token()),"ada")
        self.assertEqual(p.authenticate("Bearer "+GROK),"grokbot")
        self.assertEqual(p.authenticate("Bearer "+self.token({"scope":"other babel"})),"ada")
        self.rejected(GROK+"\n")
    def test_signature_algorithm_and_key_selection(self):
        other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.rejected(self.token(key=other))
        self.rejected(self.token(headers={"kid":"unknown"}))
        self.rejected(self.token(headers={"jku":"https://evil.example.com/key"}))
        self.rejected(self.token(headers={"crit":["unknown"]}))
        self.rejected(self.token(key="public-synthetic-HMAC-fixture-0000",algorithm="HS256"))
        self.rejected("malformed.jwt.value")
    def test_issuer_audience_and_required_claims(self):
        self.rejected(self.token({"iss":"https://other.example.com/"}))
        self.rejected(self.token({"aud":"https://other.example.com/mcp"}))
        self.rejected(self.token({"sub":None}))
        self.rejected(self.token({"azp":None}))
        self.rejected(self.token({"scope":None}))
    def test_expiry_not_before_and_lifetime(self):
        now=int(time.time())
        for changes in ({"exp":now-10},{"nbf":now+100},{"iat":now+100},
                        {"exp":now+2000},{"exp":str(now+200)},{"iat":True}):
            self.rejected(self.token(changes))
    def test_explicit_scope_and_principal_allowlists(self):
        for changes in ({"scope":"other"},{"sub":"another-user"},{"azp":"another-client"}):
            self.rejected(self.token(changes),403)
    def test_pinned_jwks_public_only_and_strength(self):
        for change in ({"d":"private-material"},{"alg":"HS256"},{"use":"enc"}):
            with self.assertRaises(BridgeError):
                self.policy(jwks={"keys":[{**self.jwk,**change}]})
        with self.assertRaises(BridgeError):
            self.policy(jwks={"keys":[self.jwk,self.jwk]})
        weak=rsa.generate_private_key(public_exponent=65537,key_size=1024)
        jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(weak.public_key()))
        jwk["kid"]="weak"
        with self.assertRaises(BridgeError): self.policy(jwks={"keys":[jwk]})
    def test_authorization_fingerprint_survives_refresh_but_not_rebinding(self):
        p=self.policy()
        before=p.agents["ada"][0]
        p.authenticate("Bearer "+self.token())
        p.authenticate("Bearer "+self.token({"exp":int(time.time())+250}))
        self.assertEqual(before,self.policy().agents["ada"][0])
        changed=copy.deepcopy(self.cfg)
        changed["oauth"]["principals"]["ada"]["subject"]="new-user"
        self.assertNotEqual(before,self.policy(changed).agents["ada"][0])
    def test_gateway_resource_metadata_challenge_and_scoped_tools(self):
        store=Store(":memory:")
        server=Gateway(0,self.policy(),"https://bridge.example.com",store,transport=FakeTransport())
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        opener=build_opener(ProxyHandler({}))
        def request(path,body=None,token=None,extra=None):
            headers={"Host":"bridge.example.com","X-Forwarded-Proto":"https",
                     "Content-Type":"application/json","Accept":"application/json, text/event-stream"}
            if token: headers["Authorization"]="Bearer "+token
            headers.update(extra or {})
            req=Request("http://127.0.0.1:"+str(server.port)+path,
                        data=None if body is None else json.dumps(body).encode(),headers=headers)
            try: response=opener.open(req,timeout=3)
            except HTTPError as exc: response=exc
            with response: return response.status,response.read(),dict(response.headers)
        try:
            for path in ("/.well-known/oauth-protected-resource","/.well-known/oauth-protected-resource/mcp"):
                status,body,_=request(path)
                self.assertEqual(status,200)
                self.assertEqual(json.loads(body)["resource"],self.cfg["oauth"]["resource"])
                self.assertNotIn("principals",body.decode())
            status,_,headers=request("/mcp",{})
            self.assertEqual(status,401)
            self.assertIn("resource_metadata=",headers["WWW-Authenticate"])
            self.assertEqual(request("/api/history",{},self.token())[0],404)
            rpc={"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
                "io.modelcontextprotocol/protocolVersion":mcp2.VERSION,
                "io.modelcontextprotocol/clientCapabilities":{}}}}
            status,body,_=request("/mcp",rpc,self.token(),
                                 {"MCP-Protocol-Version":mcp2.VERSION,"Mcp-Method":"tools/list"})
            self.assertEqual(status,200)
            for tool in json.loads(body)["result"]["tools"]:
                self.assertEqual(tool["securitySchemes"],[{"type":"oauth2","scopes":["babel"]}])
            self.assertEqual(request("/.well-known/oauth-protected-resource",
                                     extra={"X-Forwarded-Proto":"http"})[0],403)
        finally:
            server.shutdown();server.server_close();thread.join();store.close()

class TransportMechanismTests(unittest.TestCase):
    def test_pinned_address_and_original_tls_hostname(self):
        context=MagicMock()
        raw=MagicMock()
        address=(2,1,6,"",("8.8.8.8",443))
        with patch("babel.wake.public_addresses",return_value=[address]) as resolver, \
             patch("babel.wake.socket.socket",return_value=raw):
            connection=PinnedHTTPS("ada.example.com",443,timeout=10,context=context)
            connection.connect()
            resolver.assert_called_once_with("ada.example.com")
            raw.connect.assert_called_once_with(("8.8.8.8",443))
            context.wrap_socket.assert_called_once_with(raw,server_hostname="ada.example.com")
            connection.close()
    def test_redirect_is_not_followed_and_body_is_bounded(self):
        for status,body in ((302,b"redirect"),(200,b"x"*8193)):
            connection=MagicMock()
            response=connection.getresponse.return_value
            response.status=status;response.read.return_value=body
            with patch("babel.wake.PinnedHTTPS",return_value=connection):
                with self.assertRaises(CallbackError):
                    WebhookTransport(config()).post("ada","https://ada.example.com/cb",b"{}",{})
                self.assertEqual(connection.request.call_count,1)
                response.read.assert_called_once_with(8193)
                connection.close.assert_called_once()
