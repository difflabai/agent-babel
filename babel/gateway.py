"""Public MCP only. Never serves operator routes, assets or global history."""
from urllib.parse import urlsplit
import threading
from .auth import Policy, ScopedStore, public_origin
from .core import BridgeError, Store
from .mcp import dispatch
from .server import Handler, HTTP_VERSIONS, BoundedServer
from .wake import WakeConfig
from .events import EventService
from . import mcp2

class Gateway(BoundedServer):
    def __init__(self, port, policy, origin, store=None, host="127.0.0.1", wake_config=None, transport=None):
        # Validate all security configuration BEFORE listening or opening storage.
        self.origin = public_origin(origin)
        self.policy = policy
        self.policy_lock=threading.RLock()
        self.policy_file=getattr(policy,"source_file",None)
        if hasattr(policy,"oauth") and policy.oauth["resource"] != self.origin + "/mcp":
            raise BridgeError("OAuth resource must match the gateway public origin and /mcp")
        if not isinstance(policy, Policy):
            raise BridgeError("An explicit authentication policy is required")
        self.hosts = {urlsplit(self.origin).netloc}
        self.origins = {self.origin}
        self.store = store if store is not None else Store()
        self.store.sync_policy(policy)
        self.wake_config=wake_config or WakeConfig()
        self.transport=transport
        self.events = EventService(self.store, policy, wake_config or WakeConfig(), transport)
        super().__init__((host, port), GatewayHandler)
        self.port = self.server_address[1]

    def current_policy(self):
        with self.policy_lock:
            if self.policy_file:
                latest=Policy.load(self.policy_file)
                if hasattr(latest,"oauth") and latest.oauth["resource"]!=self.origin+"/mcp":
                    raise BridgeError("OAuth resource does not match this gateway",503)
                latest.lock=self.policy.lock; latest.requests=self.policy.requests
                self.store.sync_policy(latest)
                self.policy=latest
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
            if self.path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp") and hasattr(self.server.policy,"oauth"):
                self.check_edge()
                self.respond(200,self.server.current_policy().metadata())
                return
            self.authorize()
            if self.path not in ("/mcp", "/mcp/v1"):
                raise BridgeError("Not found", 404)
            self.respond(405, {"error": "JSON POST only; no SSE stream"}, extra={"Allow": "POST"})
        except BridgeError as exc:
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
    server = Gateway(port, Policy.load(auth_file), origin, host=host, wake_config=WakeConfig.load(wake_file))
    print("Agent Babel authenticated gateway ready; operator controls are private.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.store.close()
