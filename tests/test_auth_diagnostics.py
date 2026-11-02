"""Offline diagnostics regression: synthetic credentials, no server/provider I/O."""
import ast
import hashlib
import json
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

try:
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    jwt = None

from babel.core import BridgeError
from babel import oauth


@unittest.skipUnless(jwt, "Optional OAuth verification dependencies are not installed")
class AuthDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        cls.jwk.update(kid="DO_NOT_LOG_KEY_ID", alg="RS256", use="sig")

    def setUp(self):
        self.now = int(time.time())
        self.static = "DO_NOT_LOG_STATIC_CREDENTIAL_00000000000001"
        self.config = {"schema_version": 2, "agents": {
            "ada": {"recipients": ["grokbot"]},
            "grokbot": {"sha256": hashlib.sha256(self.static.encode()).hexdigest(),
                        "recipients": ["ada"]}},
            "oauth": {"issuer": "https://do-not-log-issuer.example.invalid/",
                      "resource": "https://do-not-log-resource.example.invalid/mcp",
                      "jwks_file": "unused",
                      "principals": {"ada": {"subject": "DO_NOT_LOG_SUBJECT",
                                             "client_id": "DO_NOT_LOG_CLIENT"}}}}
        self.policy = oauth.OAuthPolicy(self.config, {"keys": [self.jwk]})

    def token(self, changes=None, headers=None, key=None):
        claims = {"iss": self.config["oauth"]["issuer"],
                  "aud": self.config["oauth"]["resource"],
                  "sub": "DO_NOT_LOG_SUBJECT", "azp": "DO_NOT_LOG_CLIENT",
                  "scope": "babel", "iat": self.now-10, "exp": self.now+300}
        claims.update(changes or {})
        return jwt.encode(claims, key or self.key, algorithm="RS256",
                          headers={"kid": self.jwk["kid"], **(headers or {})})

    def check_rejection(self, header, status, message, reason):
        fingerprint = dict(self.policy.agents)
        with self.assertLogs(oauth.LOG, level="WARNING") as logs:
            with self.assertRaises(BridgeError) as error:
                self.policy.authenticate(header)
        self.assertEqual((error.exception.status, str(error.exception)), (status, message))
        self.assertEqual(self.policy.agents, fingerprint)
        self.assertEqual(len(logs.records), 1)
        record = logs.records[0]
        self.assertEqual(record.msg, "Babel authentication rejected: reason=%s status=%d")
        self.assertEqual(record.args, (reason, status))
        self.assertIsNone(record.exc_info)
        self.assertIsNone(record.stack_info)
        self.assertNotIn("DO_NOT_LOG", record.getMessage())
        if isinstance(header, str):
            self.assertNotIn(header, record.getMessage())

    def test_validation_categories_preserve_public_errors_and_hide_values(self):
        generic = "Invalid OAuth access token"
        cases = [
            (None, 401, "Agent authentication required", "authorization_missing"),
            ("Basic DO_NOT_LOG", 401, "Agent authentication required", "authorization_scheme_invalid"),
            ("Bearer " + "x"*8193, 401, "Invalid agent credential", "credential_oversized"),
            ("Bearer short", 401, "Invalid agent credential", "credential_format_invalid"),
            ("Bearer " + "x"*40, 401, "Invalid agent credential", "static_credential_unrecognized"),
            ("Bearer malformed.jwt.value", 401, generic, "token_invalid"),
            ("Bearer " + self.token({"exp": self.now-30}), 401, generic, "token_expired"),
            ("Bearer " + self.token({"iat": self.now+300}), 401, generic, "token_not_yet_valid"),
            ("Bearer " + self.token({"nbf": self.now+300}), 401, generic, "token_not_yet_valid"),
            ("Bearer " + self.token({"iat": "not-a-number"}), 401, generic, "issued_at_invalid"),
            ("Bearer " + self.token({"iss": "https://DO_NOT_LOG.invalid/"}), 401, generic, "issuer_mismatch"),
            ("Bearer " + self.token({"aud": "https://DO_NOT_LOG.invalid/mcp"}), 401, generic, "audience_mismatch"),
            ("Bearer " + self.token({"azp": None}), 401, generic, "required_claim_missing"),
            ("Bearer " + self.token(headers={"kid": "DO_NOT_LOG_UNKNOWN"}), 401, generic, "signing_key_unknown"),
            ("Bearer " + self.token(headers={"jku": "https://DO_NOT_LOG.invalid/"}), 401, generic, "token_header_rejected"),
            ("Bearer " + self.token(key=self.other_key), 401, generic, "signature_invalid"),
            ("Bearer " + self.token({"exp": self.now+1800}), 401, generic, "token_lifetime_invalid"),
            ("Bearer " + self.token({"exp": str(self.now+300)}), 401, generic, "token_lifetime_invalid"),
            ("Bearer " + self.token({"scope": "DO_NOT_LOG_SCOPE"}), 403,
             "Required OAuth scope is missing", "scope_missing"),
            ("Bearer " + self.token({"azp": "DO_NOT_LOG_OTHER_CLIENT"}), 403,
             "OAuth principal is not authorized for a bridge role", "principal_client_mismatch"),
            ("Bearer " + self.token({"sub": "DO_NOT_LOG_OTHER_SUBJECT"}), 403,
             "OAuth principal is not authorized for a bridge role", "principal_subject_mismatch"),
            ("Bearer " + self.token({"sub": "DO_NOT_LOG_OTHER_SUBJECT", "azp": "DO_NOT_LOG_OTHER_CLIENT"}), 403,
             "OAuth principal is not authorized for a bridge role", "principal_unknown"),
        ]
        for header, status, message, reason in cases:
            with self.subTest(reason=reason):
                self.check_rejection(header, status, message, reason)

    def test_valid_static_refresh_and_subscription_fingerprint_unchanged(self):
        fingerprint = dict(self.policy.agents)
        with patch.object(oauth.LOG, "warning") as log:
            self.assertEqual(self.policy.authenticate("Bearer " + self.static), "grokbot")
            self.assertEqual(self.policy.authenticate("Bearer " + self.token()), "ada")
            self.assertEqual(self.policy.authenticate("Bearer " + self.token({"iat": self.now-1})), "ada")
            log.assert_not_called()
        self.assertEqual(self.policy.agents, fingerprint)

    def test_known_subject_and_client_cannot_be_cross_paired(self):
        import copy
        config = copy.deepcopy(self.config)
        config["oauth"]["principals"]["grokbot"] = {
            "subject": "DO_NOT_LOG_OTHER_SUBJECT", "client_id": "DO_NOT_LOG_OTHER_CLIENT"}
        self.policy = oauth.OAuthPolicy(config, {"keys": [self.jwk]})
        self.check_rejection("Bearer " + self.token({"azp": "DO_NOT_LOG_OTHER_CLIENT"}), 403,
            "OAuth principal is not authorized for a bridge role", "principal_pair_mismatch")

    def test_enrollment_and_participant_checks_remain_enforced(self):
        self.policy.multi_owner = True
        self.policy.owners = {"offline": {"enabled": True}}
        self.policy.participants = {"ada": {"owner": "offline", "state": "active",
            "accepted": True, "activated_at": self.now-5, "expires": None}}
        self.check_rejection("Bearer " + self.token(), 401,
            "OAuth token predates this instance enrollment", "token_predates_enrollment")
        self.assertEqual(self.policy.authenticate("Bearer " + self.token({"iat": self.now-1})), "ada")
        self.policy.owners["offline"]["enabled"] = False
        self.check_rejection("Bearer " + self.token(), 403,
            "Participant access is unavailable", "participant_inactive")

    def test_rate_limit_unchanged(self):
        header = "Bearer " + self.token()
        with patch.object(oauth.LOG, "warning") as log:
            for _ in range(120):
                self.policy.authenticate(header)
            with self.assertRaises(BridgeError) as error:
                self.policy.authenticate(header)
            self.assertEqual((error.exception.status, str(error.exception)),
                             (429, "Agent request limit: 120 per minute"))
            log.assert_not_called()

    def test_gateway_header_rejections_without_starting_server(self):
        # Execute the actual method in isolation: no sockets, provider, or database.
        source = Path(oauth.__file__).with_name("gateway.py").read_text()
        tree = ast.parse(source)
        handler = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                       and node.name == "GatewayHandler")
        method = next(node for node in handler.body if isinstance(node, ast.FunctionDef)
                      and node.name == "authorize")
        namespace = {"BridgeError": BridgeError, "rejection": oauth.rejection}
        exec(compile(ast.Module(body=[method], type_ignores=[]), "gateway.authorize", "exec"), namespace)
        for headers, reason in (([], "authorization_missing"),
                                (["DO_NOT_LOG_1", "DO_NOT_LOG_2"], "authorization_multiple")):
            policy = Mock()
            request = SimpleNamespace(check_edge=Mock(),
                server=SimpleNamespace(current_policy=Mock(return_value=policy)),
                headers=SimpleNamespace(get_all=Mock(return_value=headers)))
            with self.assertLogs(oauth.LOG, level="WARNING") as logs:
                with self.assertRaises(BridgeError) as error:
                    namespace["authorize"](request)
            self.assertEqual((error.exception.status, str(error.exception)),
                             (401, "Agent authentication required"))
            self.assertEqual(logs.records[0].args, (reason, 401))
            policy.authenticate.assert_not_called()
            request.check_edge.assert_called_once_with()
        policy = Mock()
        request = SimpleNamespace(check_edge=Mock(),
            server=SimpleNamespace(current_policy=Mock(return_value=policy)),
            headers=SimpleNamespace(get_all=Mock(return_value=["DO_NOT_LOG_SINGLE"])))
        with patch.object(oauth.LOG, "warning") as log:
            self.assertIs(namespace["authorize"](request), policy.authenticate.return_value)
            policy.authenticate.assert_called_once_with("DO_NOT_LOG_SINGLE")
            log.assert_not_called()


if __name__ == "__main__":
    unittest.main()
