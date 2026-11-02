"""OAuth resource-server validation with an operator-pinned public JWKS.
The external provider owns authorization, PKCE, registration, login and consent.
"""
import hashlib
import json
import logging
from pathlib import Path
from urllib.parse import urlsplit
from .auth import Policy, public_origin, TOKEN
from .core import BridgeError, fields

SCOPE = "babel"
LOG = logging.getLogger(__name__)

def rejection(reason, message, status=401):
    # Fixed categories only: never log headers, tokens, claims, identities or
    # exception text. Client-visible errors remain deliberately unchanged.
    LOG.warning("Babel authentication rejected: reason=%s status=%d", reason, status)
    return BridgeError(message, status)

class OAuthPolicy(Policy):
    def __init__(self, config, jwks=None):
        oauth = config.get("oauth")
        fields(oauth, ("issuer","resource","jwks_file","principals"), ("issuer","resource","jwks_file","principals"))
        if not isinstance(oauth["issuer"],str):
            raise BridgeError("OAuth issuer must be a trusted HTTPS issuer")
        parsed = urlsplit(oauth["issuer"])
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.netloc != parsed.hostname):
            raise BridgeError("OAuth issuer must be an exact trusted HTTPS issuer")
        resource = oauth["resource"]
        if not isinstance(resource,str) or not resource.endswith("/mcp"):
            raise BridgeError("OAuth resource must be the exact public /mcp URL")
        public_origin(resource[:-4])
        principals = oauth["principals"]
        if not isinstance(principals,dict):
            raise BridgeError("Explicit OAuth principal bindings are required")
        self.bindings = {}
        identities=config.get("participants") if config.get("schema_version")==3 else config.get("agents")
        for role, value in principals.items():
            if not isinstance(identities,dict) or role not in identities:
                raise BridgeError("OAuth role must be a configured bridge agent")
            fields(value, ("subject","client_id"), ("subject","client_id"))
            if any(not isinstance(value[k],str) or not value[k] or len(value[k])>256 or "<" in value[k]
                   for k in ("subject","client_id")):
                raise BridgeError("OAuth requires actual subject and client ID allowlists")
            pair = (value["subject"],value["client_id"])
            if pair in self.bindings:
                raise BridgeError("OAuth principal bindings must be distinct")
            self.bindings[pair] = role
        base = {k:v for k,v in config.items() if k != "oauth"}
        super().__init__(base, oauth_roles=set(principals))
        self.oauth = oauth
        self.static_digests = dict(self.credential_digests)
        # Durable subscription authorization changes whenever role bindings change,
        # not whenever a short-lived access token is refreshed.
        for role, entry in list(self.agents.items()):
            fingerprint = json.dumps([oauth["issuer"],resource,principals.get(role),entry[0]],sort_keys=True,separators=(",",":"))
            self.agents[role] = (hashlib.sha256(fingerprint.encode()).hexdigest(),entry[1])
        try:
            import jwt
        except ImportError:
            raise BridgeError("OAuth mode requires the declared PyJWT/cryptography dependencies") from None
        self.jwt = jwt
        if jwks is None:
            path = Path(oauth["jwks_file"])
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
                raise BridgeError("OAuth JWKS must be an operator-managed regular public-key file")
            try:
                jwks = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError,UnicodeError):
                raise BridgeError("Invalid OAuth public JWKS") from None
        fields(jwks, ("keys",), ("keys",))
        if not isinstance(jwks["keys"],list) or not 1 <= len(jwks["keys"]) <= 8:
            raise BridgeError("OAuth JWKS needs 1–8 public signing keys")
        self.keys = {}
        try:
            for key in jwks["keys"]:
                if not isinstance(key,dict):
                    raise BridgeError("Invalid OAuth public signing keys")
                if (key.get("kty") != "RSA" or key.get("alg","RS256") != "RS256"
                        or key.get("use","sig") != "sig" or any(k in key for k in ("d","p","q","dp","dq","qi","oth"))
                        or not isinstance(key.get("kid"),str) or not key["kid"] or key["kid"] in self.keys):
                    raise BridgeError("JWKS must contain distinct public RSA signing keys only")
                parsed_key = jwt.PyJWK.from_dict(key, algorithm="RS256").key
                if parsed_key.key_size < 2048:
                    raise BridgeError("OAuth signing keys must be at least 2048 bits")
                self.keys[key["kid"]] = parsed_key
        except (ValueError,TypeError,KeyError,jwt.PyJWTError):
            raise BridgeError("Invalid OAuth public signing keys") from None

    def metadata(self):
        return {"resource":self.oauth["resource"],"authorization_servers":[self.oauth["issuer"]],
                "scopes_supported":[SCOPE],"bearer_methods_supported":["header"]}

    def authenticate(self, header):
        if not isinstance(header,str) or not header.startswith("Bearer "):
            reason = "authorization_missing" if header is None else "authorization_scheme_invalid"
            raise rejection(reason, "Agent authentication required")
        token = header[7:]
        if len(token)>8192:
            raise rejection("credential_oversized", "Invalid agent credential")
        if "." not in token:
            if not TOKEN.fullmatch(token):
                raise rejection("credential_format_invalid", "Invalid agent credential")
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            import secrets
            role = next((role for role, expected in self.static_digests.items()
                         if secrets.compare_digest(digest,expected)),None)
            if role is None:
                raise rejection("static_credential_unrecognized", "Invalid agent credential")
        else:
            reason = "token_malformed"
            try:
                header_data = self.jwt.get_unverified_header(token)
                # kid is only a lookup into already trusted local keys. Never follow
                # jku/x5u or select an algorithm from attacker-controlled input.
                if header_data.get("alg") != "RS256" or any(k in header_data for k in ("jku","x5u","jwk","crit")):
                    reason = "token_header_rejected"
                    raise ValueError()
                key = self.keys.get(header_data.get("kid"))
                if key is None:
                    reason = "signing_key_unknown"
                    raise ValueError()
                reason = "token_invalid"
                claims = self.jwt.decode(token,key,algorithms=["RS256"],issuer=self.oauth["issuer"],
                    audience=self.oauth["resource"],options={"require":["exp","iat","iss","aud","sub","azp","scope"]},leeway=0)
                if type(claims["exp"]) is not int or type(claims["iat"]) is not int or not 0 < claims["exp"]-claims["iat"] <= 900:
                    reason = "token_lifetime_invalid"
                    raise ValueError()
                if not isinstance(claims["scope"],str) or SCOPE not in claims["scope"].split():
                    raise rejection("scope_missing", "Required OAuth scope is missing", 403)
                role = self.bindings.get((claims["sub"],claims["azp"]))
                if role is None:
                    # Compare only with the existing allowlist. Emit no identity,
                    # client identifier or claim value, and authorize no new pair.
                    subject_known = any(subject == claims["sub"] for subject, _ in self.bindings)
                    client_known = any(client == claims["azp"] for _, client in self.bindings)
                    reason = {
                        (True, False): "principal_client_mismatch",
                        (False, True): "principal_subject_mismatch",
                        (True, True): "principal_pair_mismatch",
                        (False, False): "principal_unknown",
                    }[subject_known, client_known]
                    raise rejection(reason, "OAuth principal is not authorized for a bridge role", 403)
            except BridgeError:
                raise
            except self.jwt.PyJWTError as exc:
                categories = (
                    (self.jwt.ExpiredSignatureError, "token_expired"),
                    (self.jwt.ImmatureSignatureError, "token_not_yet_valid"),
                    (self.jwt.InvalidIssuedAtError, "issued_at_invalid"),
                    (self.jwt.InvalidAudienceError, "audience_mismatch"),
                    (self.jwt.InvalidIssuerError, "issuer_mismatch"),
                    (self.jwt.MissingRequiredClaimError, "required_claim_missing"),
                    (self.jwt.InvalidSignatureError, "signature_invalid"),
                )
                reason = next((label for kind, label in categories if isinstance(exc, kind)), "token_invalid")
                raise rejection(reason, "Invalid OAuth access token") from None
            except (ValueError,TypeError,KeyError):
                raise rejection(reason, "Invalid OAuth access token") from None
        try:
            self.assert_active(role)
        except BridgeError as exc:
            raise rejection("participant_inactive", str(exc), exc.status) from None
        if self.multi_owner and "." in token and claims["iat"]<self.participants[role]["activated_at"]:
            raise rejection("token_predates_enrollment", "OAuth token predates this instance enrollment")
        self.limit_request(role)
        return role
