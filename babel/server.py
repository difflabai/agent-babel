"""Loopback UI and MCP endpoint. No outbound networking."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
import json
import secrets
import threading
from .adapters import ManualAdapter, MockAdapter
from .core import AGENTS, ROOT, BridgeError, Store, fields, identifier
from .mcp import VERSIONS, dispatch

MAX_BODY = 65536
HTTP_VERSIONS = tuple(version for version in VERSIONS if version != "2024-11-05")

class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32
    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kwargs)
    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise
    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()
    def handle_error(self, *_args):
        pass  # No potentially sensitive exception contents in request logs.

class Server(BoundedServer):
    def __init__(self, port, store=None, container=False):
        super().__init__(("0.0.0.0" if container else "127.0.0.1", port), Handler)
        self.store = store if store is not None else Store()
        self.csrf = secrets.token_urlsafe(32)  # ephemeral CSRF token; no API key or persistent grant
        self.port = self.server_address[1]
        self.hosts = {"127.0.0.1:" + str(self.port), "localhost:" + str(self.port)}
        self.origins = {"http://" + value for value in self.hosts}

class Handler(BaseHTTPRequestHandler):
    server_version = "AgentBabel/0.1"
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_args):
        pass  # no URLs, message bodies, credentials, or headers in logs

    def check_request(self, csrf=False):
        if self.headers.get("Host") not in self.server.hosts:
            raise BridgeError("Invalid operator Host", 403)
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.server.origins:
            raise BridgeError("Foreign Origin denied", 403)
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise BridgeError("Cross-site access denied", 403)
        if csrf and not secrets.compare_digest(self.headers.get("X-Babel-CSRF", ""), self.server.csrf):
            raise BridgeError("Missing or invalid local UI CSRF token", 403)

    def respond(self, status, body=None, content_type="application/json", extra=None):
        payload = b"" if body is None else (
            body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8"))
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                         "img-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def mcp_role(self, path):
        if path == "/mcp":
            return "ada"
        if path.startswith("/mcp/") and path[5:] in AGENTS:
            return path[5:]
        return None

    def read_json(self):
        if self.headers.get_all("Transfer-Encoding", []):
            raise BridgeError("Transfer-Encoding is unsupported", 400)
        if len(self.headers.get_all("Content-Length", [])) != 1:
            raise BridgeError("Exactly one Content-Length is required", 411)
        if len(self.headers.get_all("Content-Type", [])) != 1 or self.headers.get_content_type() != "application/json":
            raise BridgeError("Content-Type must be application/json", 415)
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise BridgeError("A valid Content-Length is required", 411)
        if not 0 < length <= MAX_BODY:
            raise BridgeError("Request body must be 1–65536 bytes", 413)
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise BridgeError("Incomplete request body")
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise BridgeError("Invalid JSON")
        if not isinstance(value, dict):
            raise BridgeError("JSON body must be an object")
        return value

    def do_GET(self):
        try:
            self.check_request()
            url = urlsplit(self.path)
            path = url.path
            if self.mcp_role(path):
                self.respond(405, {"error": "This tools-only endpoint offers JSON POST; no SSE stream"},
                             extra={"Allow": "POST"})
            elif path in ("/", "/app.js", "/style.css"):
                name = {"/": "index.html", "/app.js": "app.js", "/style.css": "style.css"}[path]
                content_type = {"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8",
                                "style.css": "text/css; charset=utf-8"}[name]
                self.respond(200, (ROOT / "web" / name).read_bytes(), content_type)
            elif path == "/api/session":
                self.respond(200, {"csrf": self.server.csrf, "agents": list(AGENTS)})
            elif path == "/api/health":
                self.respond(200, {"status": "ok", "network": "loopback-only", "live_adapters": False,
                                  "events": False, "mcp": "tools-only", "version": "0.2.0"})
            elif path == "/api/wake-status":
                self.respond(200, self.server.store.wake_status())
            elif path == "/api/history":
                query = parse_qs(url.query)
                if set(query) - {"before"} or any(len(v) != 1 for v in query.values()):
                    raise BridgeError("Unsupported history query")
                try:
                    before = int(query["before"][0]) if "before" in query else None
                except ValueError:
                    raise BridgeError("before must be a positive sequence number")
                self.respond(200, {"messages": self.server.store.history(before=before)})
            else:
                raise BridgeError("Not found", 404)
        except BridgeError as exc:
            self.respond(exc.status, {"error": str(exc)})
        except (TimeoutError, OSError):
            self.close_connection = True
        except Exception:
            self.respond(500, {"error": "Internal bridge error; content was not logged"})

    def do_POST(self):
        try:
            path = urlsplit(self.path).path
            role = self.mcp_role(path)
            self.check_request(csrf=role is None)
            if role:
                version = self.headers.get("MCP-Protocol-Version")
                if version is not None and version not in HTTP_VERSIONS:
                    raise BridgeError("Unsupported MCP protocol version; events are not implemented")
                accept = self.headers.get("Accept", "")
                if "application/json" not in accept or "text/event-stream" not in accept:
                    raise BridgeError("MCP Accept must include application/json and text/event-stream", 406)
            data = self.read_json()
            if role:
                result = dispatch(self.server.store, role, data, versions=HTTP_VERSIONS)
                self.respond(202 if result is None else 200, result)
                return
            store = self.server.store
            if path == "/api/stage":
                fields(data, ("source", "recipient", "text", "message_id", "reply_to"),
                       ("source", "recipient", "text", "message_id"))
                identifier(data["message_id"])
                result = store.stage(**data)
            elif path in ("/api/approve", "/api/cancel", "/api/export", "/api/mock", "/api/events"):
                fields(data, ("message_id",), ("message_id",))
                mid = data["message_id"]
                if path == "/api/approve":
                    result = {"message": store.approve(mid)}
                elif path == "/api/cancel":
                    result = {"message": store.cancel(mid)}
                elif path == "/api/export":
                    result = ManualAdapter(store).receive(mid)
                elif path == "/api/mock":
                    result = MockAdapter(store).receive(mid)
                else:
                    result = {"events": store.events(mid)}
            elif path == "/api/receive":
                fields(data, ("recipient", "limit"), ("recipient",))
                result = {"messages": store.inbox(**data)}
            elif path == "/api/acknowledge":
                fields(data, ("message_id", "recipient"), ("message_id", "recipient"))
                result = {"message": store.acknowledge(receipt="manual-operator", **data)}
            else:
                raise BridgeError("Not found", 404)
            self.respond(200, result)
        except BridgeError as exc:
            self.respond(exc.status, {"error": str(exc)})
        except (TimeoutError, OSError):
            self.close_connection = True
        except Exception:
            self.respond(500, {"error": "Internal bridge error; content was not logged"})

    def do_OPTIONS(self):
        try:
            self.check_request()
            self.respond(405, {"error": "CORS is disabled"}, extra={"Allow": "GET, POST"})
        except BridgeError as exc:
            self.respond(exc.status, {"error": str(exc)})

    def do_DELETE(self):
        try:
            self.check_request()
            self.respond(405, {"error": "No MCP sessions or HTTP delete operations"},
                         extra={"Allow": "GET, POST"})
        except BridgeError as exc:
            self.respond(exc.status, {"error": str(exc)})

def run(port, container=False):
    server = Server(port, container=container)
    print("Agent Babel listening at http://127.0.0.1:" + str(server.port), flush=True)
    print("Manual handoffs and mock tests only; real apps are not connected.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.store.close()
