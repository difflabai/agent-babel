"""Recipient-bound MCP Events and leased, durable approved-message notifications."""
from datetime import datetime, timezone
import hashlib
import json
import logging
import re
import secrets
import time
from urllib.parse import urlsplit
from .core import AGENTS, BridgeError, fields
from .wake import CallbackError, WebhookTransport, key_bytes, signed_headers, GrokWebhookAdapter

EVENT_NAME = "babel.message.approved"
DEFAULT_TTL_MS = 3600000
MAX_ATTEMPTS = 8
LOG = logging.getLogger(__name__)

def iso(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def identity(role, url, name, arguments):
    return "sub_" + hashlib.sha256(canonical([role, url, name, arguments]).encode("utf-8")).hexdigest()

def definition(role):
    return {"name": EVENT_NAME, "description": "An operator-approved bridge message is available for this recipient.",
            "delivery": ["webhook"],
            "inputSchema": {"type": "object", "properties": {"recipient": {"type": "string", "enum": [role]}},
                            "required": ["recipient"], "additionalProperties": False},
            "payloadSchema": {"type": "object", "properties": {
                "message_id": {"type": "string"}, "recipient": {"type": "string"},
                "root_id": {"type": "string"}, "hops": {"type": "integer", "minimum": 1, "maximum": 4}},
                "required": ["message_id", "recipient", "root_id", "hops"], "additionalProperties": False}}

class EventError(Exception):
    def __init__(self, code, message, data=None):
        self.code, self.message, self.data = code, message, data

class EventService:
    def __init__(self, store, policy, config, transport=None):
        self.store, self.policy, self.config = store, policy, config
        self.transport = transport or WebhookTransport(config)
        self.store.sync_policy(policy)
        self.sync_grok()

    def sync_grok(self):
        routines=dict(self.config.grok_routines)
        if self.config.grok["enabled"]: routines["grokbot"]=self.config.grok
        active={}
        for role,routine in routines.items():
            if not routine["enabled"]: continue
            try: self.policy.assert_active(role)
            except BridgeError: continue
            if self.policy.multi_owner and self.policy.participants[role]["client"]!="grokbot":
                raise BridgeError("Grok wake requires a Grok participant identity")
            url=routine["url"]; self.config.destination(role,url)
            sid="grok_"+hashlib.sha256((role+":"+url).encode()).hexdigest()
            active[sid]=(role,url,self.policy.agents[role][0])
        with self.store.transaction():
            for previous in self.store.db.execute("SELECT id FROM subscriptions WHERE kind='grok' AND active=1").fetchall():
                if previous["id"] not in active:
                    self.store.db.execute("UPDATE subscriptions SET active=0,secret='' WHERE id=?",(previous["id"],))
                    self.store.db.execute("UPDATE outbox SET status='canceled',last_error='access_revoked' WHERE subscription_id=? AND status IN ('pending','leased')",(previous["id"],))
            for sid,(role,url,fingerprint) in active.items():
                old=self.store.db.execute("SELECT * FROM subscriptions WHERE id=?",(sid,)).fetchone()
                if old and old["gone"]: continue
                if old and old["active"] and old["auth_digest"]==fingerprint and old["expires"]>time.time()+3600: continue
                if not old and self.store.db.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0]>=100:
                    raise BridgeError("Subscription storage capacity reached")
                expires=time.time()+86400
                if self.policy.multi_owner: expires=min(expires,self.policy.participants[role]["expires"])
                self.store.db.execute("""INSERT INTO subscriptions
                    (id,role,url,secret,auth_digest,expires,verified_until,active,created,kind)
                    VALUES(?,?,?,'',?,?,0,1,?,'grok') ON CONFLICT(id) DO UPDATE SET
                    auth_digest=excluded.auth_digest,expires=excluded.expires,active=1""",
                    (sid,role,url,fingerprint,expires,time.time()))

    def parse(self, role, params, subscribe):
        self.policy.assert_active(role)
        fields(params, ("name", "arguments", "delivery", "cursor", "ttlMs", "maxAgeMs", "_meta")
               if subscribe else ("name", "arguments", "delivery", "_meta"),
               ("name", "arguments", "delivery"))
        if params["name"] != EVENT_NAME:
            raise EventError(-32011, "Event not found", {"kind": "event"})
        fields(params["arguments"], ("recipient",), ("recipient",))
        if params["arguments"]["recipient"] != role:
            raise EventError(-32012, "Recipient is not authorized")
        delivery = params["delivery"]
        fields(delivery, ("mode", "url", "secret") if subscribe else ("mode", "url"),
               ("mode", "url", "secret") if subscribe else ("mode", "url"))
        if delivery["mode"] != "webhook":
            raise EventError(-32014, "Only webhook delivery is supported", {"feature": "deliveryMode"})
        if not isinstance(delivery["url"], str) or len(delivery["url"]) > 2048:
            raise BridgeError("Invalid callback URL")
        if subscribe:
            try:
                self.config.destination(role, delivery["url"])
            except BridgeError:
                # Give the private operator enough information to approve the
                # native client's actual destination, without retaining secrets.
                try:
                    callback=urlsplit(delivery["url"])
                    host=callback.hostname
                    if (callback.scheme=="https" and host and callback.netloc==host
                            and "." in host and re.fullmatch(r"[a-z0-9.-]{1,253}",host)):
                        LOG.warning("Callback approval required: participant=%s callback_host=%s",role,host)
                except ValueError:
                    pass
                raise
            key_bytes(delivery["secret"])
            if params.get("cursor") is not None:
                raise EventError(-32014, "Event replay cursors are unsupported", {"feature": "cursor"})
            max_age = params.get("maxAgeMs")
            if max_age is not None and (type(max_age) is not int or max_age < 0):
                raise BridgeError("maxAgeMs must be nonnegative")
        return identity(role, delivery["url"], params["name"], params["arguments"]), delivery

    def subscribe(self, role, params):
        sid, delivery = self.parse(role, params, True)
        ttl = params.get("ttlMs", DEFAULT_TTL_MS)
        if ttl is not None and (type(ttl) is not int or ttl <= 0):
            raise BridgeError("ttlMs must be a positive integer or null")
        ttl = max(60000, min(ttl if ttl is not None else DEFAULT_TTL_MS, 86400000))
        now = time.time()
        digest = self.policy.agents[role][0]
        with self.store.lock:
            existing = self.store.db.execute("SELECT * FROM subscriptions WHERE id=?", (sid,)).fetchone()
            count = self.store.db.execute("SELECT COUNT(*) FROM subscriptions WHERE role=? AND active=1 AND expires>?",
                                         (role, now)).fetchone()[0]
        if not existing and count >= 4:
            raise EventError(-32013, "Subscription limit reached", {"limit": "subscriptions", "max": 4})
        if not (existing and existing["active"] and existing["expires"] > now and existing["verified_until"] > now
                and existing["secret"] == delivery["secret"] and existing["auth_digest"] == digest):
            challenge = secrets.token_urlsafe(24)  # single-use verification challenge, never an API key
            body = canonical({"type": "verification", "challenge": challenge}).encode("utf-8")
            wid = "msg_verification_" + secrets.token_hex(16)
            headers = signed_headers(delivery["secret"], wid, body, sid)
            try:
                status, response = self.transport.post(role, delivery["url"], body, headers)
                if not 200 <= status < 300:
                    raise CallbackError("http_5xx" if status >= 500 else "http_4xx")
                result = json.loads(response)
                if not isinstance(result, dict) or not isinstance(result.get("challenge"), str):
                    raise CallbackError("challenge_failed")
                if not secrets.compare_digest(result["challenge"].encode("utf-8"), challenge.encode("utf-8")):
                    raise CallbackError("challenge_failed")
            except (ValueError, UnicodeError):
                raise EventError(-32015, "Callback verification failed", {"reason": "challenge_failed"}) from None
            except CallbackError as exc:
                raise EventError(-32015, "Callback verification failed", {"reason": exc.reason}) from None
        self.reauthorize(role)
        expires = time.time() + ttl / 1000
        if self.policy.multi_owner: expires=min(expires,self.policy.participants[role]["expires"])
        with self.store.transaction():
            # Check quotas and the current secret again after network I/O.
            existing = self.store.db.execute("SELECT * FROM subscriptions WHERE id=?", (sid,)).fetchone()
            active = self.store.db.execute("SELECT COUNT(*) FROM subscriptions WHERE role=? AND active=1 AND expires>?",
                                          (role, time.time())).fetchone()[0]
            if not (existing and existing["active"] and existing["expires"] > time.time()) and active >= 4:
                raise EventError(-32013, "Subscription limit reached", {"limit": "subscriptions", "max": 4})
            # Reclaim inactive metadata/secrets; never delete pending active notifications.
            self.store.db.execute("UPDATE subscriptions SET active=0,secret='',old_secret=NULL WHERE expires<=?", (time.time(),))
            total = self.store.db.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0]
            if not existing and total >= 100:
                raise EventError(-32013, "Subscription storage capacity reached", {"limit": "subscription_history", "max": 100})
            if existing and existing["auth_digest"] != digest:
                self.store.db.execute("UPDATE outbox SET status='canceled',last_error='access_revoked' WHERE subscription_id=? AND status IN ('pending','leased')", (sid,))
            old = existing["secret"] if existing and existing["secret"] != delivery["secret"] else (
                existing["old_secret"] if existing and existing["rotate_until"] and existing["rotate_until"] > time.time() else None)
            self.store.db.execute("""INSERT INTO subscriptions
                (id,role,url,secret,old_secret,rotate_until,auth_digest,expires,verified_until,active,created)
                VALUES(?,?,?,?,?,?,?,?,?,1,?)
                ON CONFLICT(id) DO UPDATE SET secret=excluded.secret, old_secret=excluded.old_secret,
                rotate_until=excluded.rotate_until,auth_digest=excluded.auth_digest,expires=excluded.expires,
                verified_until=excluded.verified_until,active=1,gone=0""",
                (sid, role, delivery["url"], delivery["secret"], old, time.time()+300 if old else None,
                 digest, expires, time.time()+300, time.time()))
        return {"id": sid, "refreshBefore": iso(expires), "cursor": None, "truncated": False}

    def unsubscribe(self, role, params):
        sid, _ = self.parse(role, params, False)
        with self.store.transaction():
            self.store.db.execute("UPDATE subscriptions SET active=0,secret='',old_secret=NULL WHERE id=? AND role=?", (sid, role))
            self.store.db.execute("UPDATE outbox SET status='canceled',last_error='unsubscribed' WHERE subscription_id=? AND status IN ('pending','leased')", (sid,))
        return {}

    def reauthorize(self, role, row=None):
        policy=self.policy
        if getattr(policy,"source_file",None):
            from .auth import Policy
            policy=Policy.load(policy.source_file)
            self.store.sync_policy(policy)
            if policy.agents.get(role,(None,))[0]!=self.policy.agents.get(role,(None,))[0]:
                raise BridgeError("Participant authorization changed",403)
        policy.assert_active(role)
        if row is not None: policy.check_row(row)

    def claim(self, now=None):
        now = time.time() if now is None else now
        with self.store.transaction():
            self.store.db.execute("UPDATE outbox SET status='dead',last_error='attempt_limit' WHERE status='leased' AND lease_until<=? AND attempts>=?", (now, MAX_ATTEMPTS))
            self.store.db.execute("UPDATE outbox SET status='pending',lease_token=NULL WHERE status='leased' AND lease_until<=? AND attempts<?", (now, MAX_ATTEMPTS))
            row = self.store.db.execute("""SELECT o.* FROM outbox o JOIN subscriptions s ON s.id=o.subscription_id
                WHERE o.status='pending' AND o.next_attempt<=? ORDER BY o.seq LIMIT 1""", (now,)).fetchone()
            if not row:
                return None
            lease = secrets.token_hex(16)  # ephemeral work lease, no credential
            self.store.db.execute("UPDATE outbox SET status='leased',attempts=attempts+1,lease_until=?,lease_token=? WHERE seq=?",
                                  (now+30, lease, row["seq"]))
            return {**dict(row), "attempts": row["attempts"]+1, "lease_token": lease}

    def process_one(self, now=None):
        row = self.claim(now)
        if row is None:
            return False
        error, accepted, terminal, status = None, False, False, None
        with self.store.lock:
            subscription = self.store.db.execute("SELECT * FROM subscriptions WHERE id=?", (row["subscription_id"],)).fetchone()
            message = self.store._row(row["message_id"])
        s = dict(subscription)
        current = self.policy.agents.get(s["role"])
        if (not s["active"] or s["expires"] <= time.time() or not current or current[0] != s["auth_digest"]
                or message["recipient"] != s["role"] or message["status"] != "queued"):
            error, terminal = "inactive_or_unavailable", True
        else:
            try:
                self.reauthorize(s["role"],message)
                self.config.destination(s["role"], s["url"])
                if s["kind"] == "grok":
                    routine=self.config.grok_for(s["role"])
                    if not routine["enabled"] or routine["url"] != s["url"]:
                        raise BridgeError("Grok wake access revoked", 403)
                    status, _ = GrokWebhookAdapter(self.config, self.transport,s["role"]).send(row["body"].encode("utf-8"))
                    accepted = status == 200
                else:
                    status, accepted = self.send_mcp(s, row)
                if not accepted:
                    error = "http_5xx" if status >= 500 else "explicit_rejection"
                    terminal = status not in (408, 429) and status < 500
            except CallbackError as exc:
                error = "uncertain_timeout" if exc.reason == "timeout" else exc.reason
                terminal = error in ("challenge_failed", "http_4xx")
            except BridgeError:
                error, terminal = "access_revoked", True
            except Exception:
                error = "transport_error"
        with self.store.transaction():
            state = "accepted" if accepted else ("dead" if terminal or row["attempts"] >= MAX_ATTEMPTS else "pending")
            delay = min(900, 5 * 2 ** (row["attempts"]-1))
            self.store.db.execute("""UPDATE outbox SET status=?,next_attempt=?,last_error=?,lease_token=NULL,lease_until=NULL
                WHERE seq=? AND status='leased' AND lease_token=?""",
                (state, time.time()+delay, error, row["seq"], row["lease_token"]))
            if status == 410:
                self.store.db.execute("UPDATE subscriptions SET active=0,secret='',old_secret=NULL,gone=1 WHERE id=?", (s["id"],))
                self.store.db.execute("UPDATE outbox SET status='canceled',last_error='subscription_gone' WHERE subscription_id=? AND status IN ('pending','leased')", (s["id"],))
        return True

    def send_mcp(self, s, row):
        old = s["old_secret"] if s["rotate_until"] and s["rotate_until"] > time.time() else None
        body = row["body"].encode("utf-8")
        headers = signed_headers(s["secret"], row["event_id"], body, s["id"], old)
        status, _ = self.transport.post(s["role"], s["url"], body, headers)
        return status, 200 <= status < 300
