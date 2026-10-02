"""Hash-only, agent-bound bearer configuration. No generated credentials."""
import hashlib
import json
from pathlib import Path
import re
import secrets
import threading
import time
from urllib.parse import urlsplit
from .core import AGENTS, BridgeError, fields

TOKEN = re.compile(r"[A-Za-z0-9_-]{32,256}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")

def public_origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment
            or parsed.netloc != parsed.hostname or "." not in parsed.hostname
            or not re.fullmatch(r"[a-z0-9.-]+", parsed.hostname)):
        raise BridgeError("BABEL_PUBLIC_ORIGIN must be https:// followed by a lowercase DNS hostname")
    return value

class Policy:
    def __init__(self, config, oauth_roles=()):
        self.multi_owner=False
        self.lock=threading.Lock(); self.requests={}
        if isinstance(config,dict) and config.get("schema_version")==3 and type(config.get("schema_version")) is int:
            from .participants import configure
            configure(self,config,oauth_roles)
            return
        fields(config, ("schema_version", "agents"), ("schema_version", "agents"))
        if config["schema_version"] not in (1,2) or type(config["schema_version"]) is not int:
            raise BridgeError("Unsupported authentication schema")
        agents = config["agents"]
        if not isinstance(agents, dict) or not agents or set(agents) - set(AGENTS):
            raise BridgeError("Authentication requires named bridge agents")
        self.agents = {}
        seen = set()
        for role, entry in agents.items():
            fields(entry, ("sha256", "recipients"), ("recipients",) if role in oauth_roles else ("sha256", "recipients"))
            digest, recipients = entry.get("sha256"), entry["recipients"]
            if not (digest is None and role in oauth_roles) and (not isinstance(digest, str) or not DIGEST.fullmatch(digest) or digest == "0" * 64 or digest in seen):
                raise BridgeError("Each agent needs a distinct non-placeholder SHA-256 token digest")
            if (not isinstance(recipients, list) or not recipients or any(not isinstance(r,str) for r in recipients) or len(set(recipients)) != len(recipients)
                    or any(r not in agents or r == role for r in recipients)):
                raise BridgeError("Recipients must be distinct configured agents other than the sender")
            if digest:
                seen.add(digest)
            self.agents[role] = (digest, frozenset(recipients))
        self.credential_digests={r:e[0] for r,e in self.agents.items() if e[0]}
        self.lock = threading.Lock()
        self.requests = {}

    @classmethod
    def load(cls, filename):
        path = Path(filename)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise BridgeError("Authentication file must be a regular file of at most 64 KiB")
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(config,dict) and "oauth" in config:
                from .oauth import OAuthPolicy
                result=OAuthPolicy(config)
            else:
                result=cls(config)
            result.source_file=str(path)
            return result
        except (ValueError, UnicodeError, TypeError):
            raise BridgeError("Invalid authentication configuration") from None

    def authenticate(self, header):
        if not isinstance(header, str) or not header.startswith("Bearer "):
            raise BridgeError("Agent authentication required", 401)
        token = header[7:]
        if not TOKEN.fullmatch(token):
            raise BridgeError("Invalid agent credential", 401)
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        role = None
        for candidate, expected in self.credential_digests.items():
            if expected and secrets.compare_digest(digest, expected):
                role = candidate
        if role is None:
            raise BridgeError("Invalid agent credential", 401)
        self.assert_active(role)
        self.limit_request(role)
        return role

    def assert_active(self, role):
        if role not in self.agents: raise BridgeError("Participant access is unavailable",403)
        if self.multi_owner:
            entry=self.participants[role]; now=time.time()
            if (entry["state"]!="active" or not entry["accepted"] or not self.owners[entry["owner"]]["enabled"]
                    or now<entry["activated_at"]
                    or (entry["expires"] is not None and now>=entry["expires"])):
                raise BridgeError("Participant access is unavailable",403)

    def assert_route(self, conversation, source, recipient):
        if not isinstance(source,str) or not isinstance(recipient,str) or (conversation is not None and not isinstance(conversation,str)):
            raise BridgeError("Invalid conversation route",403)
        self.assert_active(source); self.assert_active(recipient)
        if self.multi_owner:
            if (conversation,source,recipient) not in self.routes:
                raise BridgeError("Conversation route is not permitted",403)
        elif conversation is not None or recipient not in self.agents[source][1]:
            raise BridgeError("Agent route is not permitted",403)

    def auto_approves(self, conversation, source, recipient):
        self.assert_route(conversation,source,recipient)
        return (self.multi_owner and
                self.conversations[conversation].get("approval",self.approval_mode)=="automatic")

    def check_row(self, row):
        self.assert_route(row.get("conversation_id"),row["source"],row["recipient"])
        if self.multi_owner and (row.get("source_owner")!=self.participants[row["source"]]["owner"]
                or row.get("recipient_owner")!=self.participants[row["recipient"]]["owner"]):
            raise BridgeError("Message binding is unavailable",403)

    def visible_pairs(self, role):
        self.assert_active(role)
        if not self.multi_owner:
            return [(None,s,r) for s,entry in self.agents.items() for r in entry[1] if role in (s,r)]
        result=[]
        for route in sorted(self.routes):
            if role in route[1:]:
                try: self.assert_route(*route)
                except BridgeError: continue
                result.append(route)
        return result

    def limit_request(self, role):
        # Bounded by fixed roles; no attacker-controlled map keys.
        now = time.monotonic()
        with self.lock:
            for key in list(self.requests):
                if not self.requests[key] or self.requests[key][-1]<=now-60: self.requests.pop(key,None)
            if role not in self.requests and len(self.requests)>=128:
                raise BridgeError("Request budget capacity reached",429)
            entries = [t for t in self.requests.get(role, ()) if t > now - 60]
            if len(entries) >= 120:
                raise BridgeError("Agent request limit: 120 per minute", 429)
            entries.append(now)
            self.requests[role] = entries

class ScopedStore:
    """Defense in depth: only authenticated role and permitted outgoing routes."""
    def __init__(self, store, role, recipients, policy=None):
        self.store, self.role, self.recipients = store, role, recipients
        self.policy=policy
        if policy: store.sync_policy(policy)

    def guard(self):
        if not self.policy: return
        if getattr(self.policy,"source_file",None):
            latest=Policy.load(self.policy.source_file)
            self.store.sync_policy(latest)
            if latest.agents.get(self.role,(None,))[0]!=self.policy.agents.get(self.role,(None,))[0]:
                raise BridgeError("Participant authorization changed",403)
            self.policy=latest
        else: self.store.sync_policy(self.policy)
        self.policy.assert_active(self.role)

    def stage(self, source, recipient, **kwargs):
        self.guard()
        if not isinstance(source,str) or not isinstance(recipient,str) or source != self.role or recipient not in self.recipients:
            raise BridgeError("Agent route is not permitted", 403)
        if self.policy:
            self.policy.assert_route(kwargs.get("conversation_id"),source,recipient)
            kwargs["policy"]=self.policy
        parent = kwargs.get("reply_to")
        if parent:
            self.message_status(parent, self.role)
        return self.store.stage(source, recipient, **kwargs)

    def inbox(self, role, **kwargs):
        self.guard()
        if role != self.role:
            raise BridgeError("Agent identity mismatch", 403)
        if self.policy: kwargs["visibility"]=self.policy.visible_pairs(role)
        return self.store.inbox(role, **kwargs)

    def contacts(self, role):
        self.guard()
        if role != self.role:
            raise BridgeError("Agent identity mismatch",403)
        if self.policy:
            routes=self.policy.visible_pairs(role)
        else:
            routes=[(None,role,recipient) for recipient in sorted(self.recipients)]
        return [{"recipient":recipient,"conversation_id":conversation}
                for conversation,source,recipient in routes if source==role]

    def acknowledge(self, message_id, role, claim_id=None):
        self.guard()
        if role != self.role:
            raise BridgeError("Agent identity mismatch", 403)
        row = self.message_status(message_id, role)
        if row["recipient"] != role:
            raise BridgeError("Message not available to recipient", 404)
        if claim_id is None:
            raise BridgeError("Public receipt requires claim_message and its claim_id", 409)
        return self.store.acknowledge_claim(message_id, role, claim_id)

    def history(self, role, **kwargs):
        self.guard()
        if role != self.role:
            raise BridgeError("Agent identity mismatch", 403)
        if self.policy: kwargs["visibility"]=self.policy.visible_pairs(role)
        return self.store.history(role, **kwargs)

    def message_status(self, message_id, role):
        self.guard()
        if role != self.role:
            raise BridgeError("Agent identity mismatch", 403)
        if self.policy: self.policy.assert_active(role)
        row=self.store.message_status(message_id,role)
        if self.policy:
            try: self.policy.check_row(row)
            except BridgeError: raise BridgeError("Bridge message not found",404) from None
        return row

    def claim_message(self, message_id, role, claim_id):
        self.guard()
        if role != self.role:
            raise BridgeError("Agent identity mismatch", 403)
        row = self.message_status(message_id, role)
        if row["recipient"] != role:
            raise BridgeError("Bridge message not found", 404)
        return self.store.claim_message(message_id, role, claim_id)
