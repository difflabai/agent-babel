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
        self.lock = threading.Lock()
        self.requests = {}

    @classmethod
    def load(cls, filename):
        path = Path(filename)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 32768:
            raise BridgeError("Authentication file must be a regular file of at most 32 KiB")
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(config,dict) and "oauth" in config:
                from .oauth import OAuthPolicy
                return OAuthPolicy(config)
            return cls(config)
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
        for candidate, (expected, _) in self.agents.items():
            if expected and secrets.compare_digest(digest, expected):
                role = candidate
        if role is None:
            raise BridgeError("Invalid agent credential", 401)
        self.limit_request(role)
        return role

    def limit_request(self, role):
        # Bounded by fixed roles; no attacker-controlled map keys.
        now = time.monotonic()
        with self.lock:
            entries = [t for t in self.requests.get(role, ()) if t > now - 60]
            if len(entries) >= 120:
                raise BridgeError("Agent request limit: 120 per minute", 429)
            entries.append(now)
            self.requests[role] = entries

class ScopedStore:
    """Defense in depth: only authenticated role and permitted outgoing routes."""
    def __init__(self, store, role, recipients):
        self.store, self.role, self.recipients = store, role, recipients

    def stage(self, source, recipient, **kwargs):
        if source != self.role or recipient not in self.recipients:
            raise BridgeError("Agent route is not permitted", 403)
        parent = kwargs.get("reply_to")
        if parent:
            self.store.message_status(parent, self.role)
        return self.store.stage(source, recipient, **kwargs)

    def inbox(self, role, **kwargs):
        if role != self.role:
            raise BridgeError("Agent identity mismatch", 403)
        return self.store.inbox(role, **kwargs)

    def acknowledge(self, message_id, role, claim_id=None):
        if role != self.role:
            raise BridgeError("Agent identity mismatch", 403)
        row = self.store.message_status(message_id, role)
        if row["recipient"] != role:
            raise BridgeError("Message not available to recipient", 404)
        if claim_id is None:
            raise BridgeError("Public receipt requires claim_message and its claim_id", 409)
        return self.store.acknowledge_claim(message_id, role, claim_id)

    def history(self, role, **kwargs):
        if role != self.role:
            raise BridgeError("Agent identity mismatch", 403)
        return self.store.history(role, **kwargs)

    def message_status(self, message_id, role):
        if role != self.role:
            raise BridgeError("Agent identity mismatch", 403)
        return self.store.message_status(message_id, role)

    def claim_message(self, message_id, role, claim_id):
        if role != self.role:
            raise BridgeError("Agent identity mismatch", 403)
        row = self.store.message_status(message_id, role)
        if row["recipient"] != role:
            raise BridgeError("Bridge message not found", 404)
        return self.store.claim_message(message_id, role, claim_id)
