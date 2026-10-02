"""Standard Webhooks HTTPS transport. Disabled until an operator enables egress."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import base64
import hashlib
import hmac
from http.client import HTTPSConnection
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit
from .core import AGENTS, BridgeError, fields

class CallbackError(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)  # Never include callback URLs, response bodies or secrets.

def key_bytes(secret):
    if not isinstance(secret, str) or not secret.startswith("whsec_") or len(secret) > 100:
        raise BridgeError("A Standard Webhooks whsec_ signing secret is required")
    try:
        key = base64.b64decode(secret[6:], validate=True)
    except (ValueError, TypeError):
        raise BridgeError("Invalid signing secret") from None
    if not 24 <= len(key) <= 64:
        raise BridgeError("Signing key must decode to 24–64 bytes")
    return key

def signed_headers(secret, webhook_id, body, subscription_id, old_secret=None, signed_at=None):
    stamp = str(int(time.time()) if signed_at is None else signed_at)
    signed = webhook_id.encode("ascii") + b"." + stamp.encode("ascii") + b"." + body
    signatures = []
    for value in (secret, old_secret):
        if value:
            signature = base64.b64encode(hmac.new(key_bytes(value), signed, hashlib.sha256).digest()).decode("ascii")
            signatures.append("v1," + signature)
    return {"Content-Type": "application/json", "webhook-id": webhook_id,
            "webhook-timestamp": stamp, "webhook-signature": " ".join(signatures),
            "X-MCP-Subscription-Id": subscription_id}

class WakeConfig:
    def __init__(self, config=None):
        config = config or {"enabled": False, "callback_hosts": {}}
        fields(config, ("enabled", "callback_hosts", "grok"), ("enabled", "callback_hosts"))
        if type(config["enabled"]) is not bool or not isinstance(config["callback_hosts"], dict):
            raise BridgeError("Invalid wake configuration")
        self.enabled = config["enabled"]
        self.grok = config.get("grok", {"enabled": False})
        fields(self.grok, ("enabled", "url", "sender_key"), ("enabled",))
        if type(self.grok["enabled"]) is not bool:
            raise BridgeError("Invalid Grok wake configuration")
        if self.grok["enabled"]:
            fields(self.grok, ("enabled", "url", "sender_key"), ("enabled", "url", "sender_key"))
            key = self.grok["sender_key"]
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._~+/-]{20,512}=*", key):
                raise BridgeError("Grok sender key must be a non-placeholder Bearer credential")
        self.hosts = {}
        for role, hosts in config["callback_hosts"].items():
            if role not in AGENTS or not isinstance(hosts, list) or len(hosts) > 8:
                raise BridgeError("Invalid callback allowlist")
            if any(not isinstance(h, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", h)
                   or "." not in h or h.endswith(".invalid") for h in hosts):
                raise BridgeError("Callback allowlist must contain actual approved DNS hostnames")
            self.hosts[role] = frozenset(hosts)
        if self.grok["enabled"]:
            self.destination("grokbot", self.grok["url"])
        if self.enabled and not self.hosts:
            raise BridgeError("Enabled wakes require recipient callback host allowlists")

    @classmethod
    def load(cls, filename=None):
        if not filename:
            return cls()
        path = Path(filename)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
            raise BridgeError("Wake config must be a regular file of at most 8 KiB")
        try:
            return cls(json.loads(path.read_text(encoding="utf-8")))
        except (ValueError, UnicodeError, TypeError):
            raise BridgeError("Invalid wake configuration") from None

    def destination(self, role, url):
        if not self.enabled:
            raise BridgeError("Wake delivery is disabled until explicitly configured", 403)
        if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in url):
            raise BridgeError("Invalid callback URL")
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or parsed.query
                or not parsed.hostname or parsed.netloc != parsed.hostname or not parsed.path
                or parsed.hostname not in self.hosts.get(role, ())):
            raise BridgeError("Callback must use an approved recipient HTTPS hostname on port 443; no URL credentials or query")
        return parsed

DNS_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="babel-dns")
DNS_SLOTS = threading.BoundedSemaphore(2)

def resolve_bounded(host):
    if not DNS_SLOTS.acquire(blocking=False):
        raise CallbackError("timeout")
    future = DNS_POOL.submit(socket.getaddrinfo, host, 443, type=socket.SOCK_STREAM)
    future.add_done_callback(lambda _future: DNS_SLOTS.release())
    try:
        return future.result(timeout=3)
    except FutureTimeout:
        raise CallbackError("timeout") from None

def public_addresses(host):
    try:
        addresses = resolve_bounded(host)
    except OSError:
        raise CallbackError("connection_refused") from None
    if not addresses:
        raise CallbackError("connection_refused")
    for family, kind, proto, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if (not ip.is_global or ip.is_multicast or ip.is_unspecified
                or getattr(ip, "ipv4_mapped", None) is not None
                or getattr(ip, "sixtofour", None) is not None
                or getattr(ip, "teredo", None) is not None
                or ip in ipaddress.ip_network("64:ff9b::/96")
                or ip in ipaddress.ip_network("64:ff9b:1::/48")):
            raise CallbackError("connection_refused")
    return addresses

class PinnedHTTPS(HTTPSConnection):
    def connect(self):
        addresses = public_addresses(self.host)
        family, kind, proto, _, address = addresses[0]
        raw = socket.socket(family, kind, proto)
        try:
            raw.settimeout(self.timeout)
            raw.connect(address)  # No second DNS resolution, proxy or redirect.
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise

def interrupt_socket(connection):
    try:
        if connection.sock:
            connection.sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

class WebhookTransport:
    def __init__(self, config):
        self.config = config

    def post(self, role, url, body, headers):
        parsed = self.config.destination(role, url)
        if len(body) > 262144:
            raise CallbackError("http_4xx")
        connection = PinnedHTTPS(parsed.hostname, 443, timeout=10, context=ssl.create_default_context())
        timer = None
        try:
            connection.connect()
            # Total connection I/O bound, including a slow trickle response.
            timer = threading.Timer(10, lambda: interrupt_socket(connection))
            timer.daemon = True
            timer.start()
            connection.request("POST", parsed.path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(8193)
            if len(response_body) > 8192:
                raise CallbackError("challenge_failed")
            if 300 <= response.status < 400:
                raise CallbackError("http_4xx")  # Redirects never followed.
            return response.status, response_body
        except (socket.timeout, TimeoutError):
            raise CallbackError("timeout") from None
        except ssl.SSLError:
            raise CallbackError("tls_error") from None
        except (OSError, ValueError):
            raise CallbackError("connection_refused") from None
        finally:
            if timer:
                timer.cancel()
            connection.close()

class GrokWebhookAdapter:
    """User-supplied routine contract: Bearer JSON POST, only 200 accepts wake."""
    def __init__(self, config, transport=None):
        self.config, self.transport = config, transport or WebhookTransport(config)

    def send(self, body):
        if not self.config.enabled or not self.config.grok["enabled"]:
            raise BridgeError("Grok wake is disabled", 403)
        packet = json.loads(body)
        if set(packet) != {"message_id", "event", "to", "from"} or packet["to"] != "grokbot" or packet["event"] != "bridge.message_ready":
            raise BridgeError("Invalid Grok wake envelope")
        return self.transport.post("grokbot", self.config.grok["url"], body,
            {"Authorization": "Bearer " + self.config.grok["sender_key"], "Content-Type": "application/json"})
