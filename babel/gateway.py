"""Public MCP only. Never serves operator routes, assets or global history."""
from urllib.parse import urlsplit
import threading
import os
from .auth import Policy, ScopedStore, public_origin
from .core import BridgeError, Store
from .mcp import dispatch
from .server import Handler, HTTP_VERSIONS, BoundedServer
from .wake import WakeConfig
from .events import EventService
from . import mcp2
from .channel_events import ApprovalSource, STREAM_HEADER, STREAM_VERSION, MAX_STREAMS, cursor

class Gateway(BoundedServer):
    def __init__(self, port, policy, origin, store=None, host="127.0.0.1", wake_config=None, transport=None, synthetic_trial=False, channel_recipients=()):
        # Validate all security configuration BEFORE listening or opening storage.
        self.origin = public_origin(origin)
        self.policy = policy
        self.policy_lock=threading.RLock()
        self.policy_file=getattr(policy,"source_file",None)
        if hasattr(policy,"oauth") and policy.oauth["resource"] != self.origin + "/mcp":
            raise BridgeError("OAuth resource must match the gateway public origin and /mcp")
        if not isinstance(policy, Policy):
            raise BridgeError("An explicit authentication policy is required")
        if type(synthetic_trial) is not bool or (synthetic_trial and not policy.multi_owner):
            raise BridgeError("Synthetic trial requires an explicit participant policy")
        if (not isinstance(channel_recipients, (tuple, list)) or len(channel_recipients) > MAX_STREAMS
                or any(not isinstance(r, str) for r in channel_recipients)
                or len(set(channel_recipients)) != len(channel_recipients)):
            raise BridgeError("Channel recipients must be an explicit bounded list")
        for role in channel_recipients:
            policy.assert_active(role)
            if not policy.multi_owner or policy.participants[role]["client"] != "claude" or not policy.agents[role][0]:
                raise BridgeError("Channel stream requires an existing static Claude participant")
        self.synthetic = None
        if synthetic_trial:
            from .synthetic import SyntheticTransfers
            self.synthetic = SyntheticTransfers()
        self.hosts = {urlsplit(self.origin).netloc}
        self.origins = {self.origin}
        self.store = store if store is not None else Store()
        self.policy=self.store.authorized_policy(policy)
        self.store.sync_policy(self.policy)
        self.wake_config=wake_config or WakeConfig()
        self.transport=transport
        self.events = EventService(self.store, self.policy, wake_config or WakeConfig(), transport)
        self.approvals = None
        super().__init__((host, port), GatewayHandler)
        self.port = self.server_address[1]

        try:
            if channel_recipients:
                self.approvals = ApprovalSource(self.store, channel_recipients)
        except Exception:
            super().server_close()
            raise

    def server_close(self):
        if self.approvals:
            self.approvals.close()
        super().server_close()

    def service_actions(self):
        # The existing server loop expires RAM payloads even with no tool traffic.
        if self.synthetic is not None:
            self.synthetic.expire()
        if self.store.sessions:
            try:self.store.sessions.cleanup()
            except BridgeError as exc:
                if exc.status!=503:raise

    def current_policy(self):
        with self.policy_lock:
            if self.policy_file:
                latest=Policy.load(self.policy_file)
                if hasattr(latest,"oauth") and latest.oauth["resource"]!=self.origin+"/mcp":
                    raise BridgeError("OAuth resource does not match this gateway",503)
                latest.lock=self.policy.lock; latest.requests=self.policy.requests
                self.policy=latest
            self.policy=self.store.authorized_policy(self.policy)
            self.store.sync_policy(self.policy)
            return self.policy

class GatewayHandler(Handler):
    def check_edge(self):
        if len(self.headers.get_all("Host", [])) != 1 or self.headers.get("Host") not in self.server.hosts:
            raise BridgeError("Invalid gateway Host", 403)
        if self.headers.get_all("X-Forwarded-Proto", []) != ["https"]:
            raise BridgeError("Trusted HTTPS proxy is required", 403)
        origin = self.headers.get_all("Origin", [])
        if origin and (len(origin) != 1 or origin[0] not in self.server.origins):
            raise BridgeError("Foreign Origin denied", 403)
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise BridgeError("Cross-site access denied", 403)

    def authorize(self):
        # Backend is exposed only to a trusted TLS reverse proxy. It must replace
        # Host/forwarding headers; forwarding headers are NOT an authentication method.
        self.check_edge()
        self.request_policy=self.server.current_policy()
        headers = self.headers.get_all("Authorization", [])
        if len(headers) != 1:
            raise BridgeError("Agent authentication required", 401)
        return self.request_policy.authenticate(headers[0])

    def fail(self, exc):
        extra = None
        if exc.status in (401,403) and hasattr(self.server.policy,"oauth"):
            challenge = 'Bearer resource_metadata="' + self.server.origin + '/.well-known/oauth-protected-resource", scope="babel", error="' + ("invalid_token" if exc.status == 401 else "insufficient_scope") + '"'
            extra = {"WWW-Authenticate": challenge}
        elif exc.status == 401:
            extra = {"WWW-Authenticate": 'Bearer realm="agent-babel"'}
        if exc.status == 429:
            extra = {"Retry-After": "60"}
        self.close_connection = True
        self.respond(exc.status, {"error": str(exc)}, extra=extra)

    def do_GET(self):
        # Empty loopback-only liveness; no agent/API data and no token required.
        if (self.path == "/healthz" and self.client_address[0] in ("127.0.0.1", "::1")
                and self.headers.get("Host") == "127.0.0.1:" + str(self.server.port)):
            self.respond(200, {"status": "ok"})
            return
        try:
            if self.path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
                self.check_edge()
                policy=self.server.current_policy()
                metadata=(policy.metadata() if hasattr(policy,"oauth") else
                          {"resource":self.server.origin+"/mcp", "bearer_methods_supported":["header"]})
                self.respond(200,metadata)
                return
            role = self.authorize()
            if self.path not in ("/mcp", "/mcp/v1"):
                raise BridgeError("Not found", 404)
            if self.path == "/mcp/v1" and self.headers.get(STREAM_HEADER):
                if not self.server.approvals:
                    raise BridgeError("Approval stream is disabled", 404)
                if self.headers.get_all(STREAM_HEADER) != [STREAM_VERSION]:
                    raise BridgeError("Unsupported approval stream version")
                if self.headers.get_all("MCP-Protocol-Version") != ["2025-11-25"]:
                    raise BridgeError("Approval stream requires MCP 2025-11-25")
                if "text/event-stream" not in self.headers.get("Accept", ""):
                    raise BridgeError("Approval stream requires text/event-stream", 406)
                if len(self.headers.get_all("Last-Event-ID", [])) > 1:
                    raise BridgeError("Exactly one approval cursor is permitted")
                after = cursor(self.headers.get("Last-Event-ID"))
                self.server.approvals.serve(self, role, self.request_policy.agents[role][0], after)
                return
            self.respond(405, {"error": "JSON POST only; no SSE stream"}, extra={"Allow": "POST"})
        except BridgeError as exc:
            if getattr(self, "approval_stream_started", False):
                self.close_connection = True  # Never append JSON to an open SSE frame.
            else:
                self.fail(exc)
        except (TimeoutError, OSError):
            self.close_connection = True

    def do_POST(self):
        try:
            role = self.authorize()
            if self.path not in ("/mcp", "/mcp/v1"):
                raise BridgeError("Not found", 404)
            modern = self.path == "/mcp"
            version = self.headers.get("MCP-Protocol-Version")
            if not modern and version is not None and version not in HTTP_VERSIONS:
                raise BridgeError("Unsupported MCP protocol version")
            accept = self.headers.get("Accept", "")
            if "application/json" not in accept or "text/event-stream" not in accept:
                raise BridgeError("MCP Accept must include application/json and text/event-stream", 406)
            request = self.read_json()
            scoped = ScopedStore(self.server.store, role, self.request_policy.agents[role][1],self.request_policy)
            scoped.synthetic = self.server.synthetic
            wake_config=self.server.wake_config
            if getattr(wake_config,"source_file",None): wake_config=WakeConfig.load(wake_config.source_file)
            events=EventService(self.server.store,self.request_policy,wake_config,self.server.transport)
            if modern:
                status, result = mcp2.dispatch(scoped, role, request, events, self.headers)
                self.respond(status, result)
            else:
                result = dispatch(scoped, role, request, versions=HTTP_VERSIONS)
                self.respond(202 if result is None else 200, result)
        except BridgeError as exc:
            self.fail(exc)
        except (TimeoutError, OSError):
            self.close_connection = True
        except Exception:
            self.close_connection = True
            self.respond(500, {"error": "Internal bridge error; content was not logged"})

    def do_OPTIONS(self):
        self.denied_method()

    def do_DELETE(self):
        self.denied_method()

    def do_PUT(self):
        self.denied_method()

    def do_PATCH(self):
        self.denied_method()

    def do_HEAD(self):
        self.denied_method()

    def denied_method(self):
        try:
            self.authorize()
            if self.path not in ("/mcp", "/mcp/v1"):
                raise BridgeError("Not found", 404)
            self.respond(405, {"error": "Method unsupported"}, extra={"Allow": "POST"})
        except BridgeError as exc:
            self.fail(exc)

def run_gateway(port, auth_file, origin, host="127.0.0.1", wake_file=None):
    trial = os.environ.get("BABEL_SYNTHETIC_TRIAL", "0")
    if trial not in ("0", "1"):
        raise BridgeError("BABEL_SYNTHETIC_TRIAL must be 0 or 1")
    recipients = os.environ.get("BABEL_CHANNEL_RECIPIENTS", "")
    store=Store()
    if os.environ.get("BABEL_TRUSTED_ACCOUNTS_FILE"):
        from .session_leases import SessionLeases, load_accounts
        SessionLeases(store,load_accounts(os.environ["BABEL_TRUSTED_ACCOUNTS_FILE"]))
    server = Gateway(port, Policy.load(auth_file), origin, store=store, host=host,
                     wake_config=WakeConfig.load(wake_file), synthetic_trial=trial == "1",
                     channel_recipients=tuple(recipients.split(",")) if recipients else ())
    print("Agent Babel authenticated gateway ready; operator controls are private.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.store.close()
