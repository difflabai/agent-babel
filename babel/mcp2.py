"""Stateless MCP 2026-07-28 tools + OpenAI's documented draft Events subset."""
import base64
from .core import BridgeError, fields
from .events import EventError, definition
from .mcp import INSTRUCTIONS, dispatch as legacy_dispatch

VERSION = "2026-07-28"
PREFIX = "io.modelcontextprotocol/"

def rpc_error(request, code, message, data=None):
    result = {"jsonrpc": "2.0", "error": {"code": code, "message": message}}
    if isinstance(request, dict) and type(request.get("id")) in (str, int):
        result["id"] = request["id"]
    if data is not None:
        result["error"]["data"] = data
    return result

def decoded_header(value):
    if not isinstance(value, str) or not value or any(ord(c)<32 or ord(c)>126 for c in value) or value != value.strip():
        raise BridgeError("Invalid MCP header")
    if value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
        except (ValueError, UnicodeError):
            raise BridgeError("Invalid MCP header encoding") from None
    return value

def dispatch(store, role, request, events, headers):
    if (not isinstance(request, dict) or request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str)
            or type(request.get("id")) not in (str, int)):
        return 400, rpc_error(request, -32600, "Invalid JSON-RPC request")
    params = request.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("_meta"), dict):
        return 400, rpc_error(request, -32602, "Required per-request metadata is missing")
    meta = params["_meta"]
    version = meta.get(PREFIX+"protocolVersion")
    capabilities = meta.get(PREFIX+"clientCapabilities")
    if not isinstance(version, str) or not isinstance(capabilities, dict):
        return 400, rpc_error(request, -32602, "Required per-request metadata is missing")
    if version != VERSION:
        return 400, rpc_error(request, -32022, "Unsupported protocol version", {"supported":[VERSION], "requested":version})
    method = request["method"]
    try:
        for name, expected in (("MCP-Protocol-Version", version), ("Mcp-Method", method)):
            values = headers.get_all(name, [])
            if len(values) != 1 or values[0] != expected:
                raise BridgeError("MCP headers do not match request")
        if method in ("tools/call", "resources/read", "prompts/get"):
            values = headers.get_all("Mcp-Name", [])
            if len(values) != 1 or decoded_header(values[0]) != params.get("name", params.get("uri")):
                raise BridgeError("MCP headers do not match request")
    except BridgeError:
        return 400, rpc_error(request, -32020, "Missing, malformed or mismatched MCP headers")
    try:
        if method == "server/discover":
            fields(params, ("_meta",))
            result = {"supportedVersions": [VERSION], "capabilities":{"tools":{}, "events":{}},
                      "instructions": INSTRUCTIONS, "ttlMs":0, "cacheScope":"private"}
        elif method == "ping":
            fields(params, ("_meta",))
            result = {}
        elif method in ("tools/list", "tools/call"):
            if method == "tools/list":
                fields(params, ("_meta", "cursor"))
                if params.get("cursor") is not None:
                    raise BridgeError("No additional tool pages")
            response = legacy_dispatch(store, role, request)
            if "error" in response:
                return 200, response
            result = response["result"]
            if method == "tools/list" and hasattr(events.policy,"oauth"):
                result["tools"] = [{**tool,"securitySchemes":[{"type":"oauth2","scopes":["babel"]}]} for tool in result["tools"]]
        elif method == "events/list":
            fields(params, ("_meta", "cursor"))
            if params.get("cursor") is not None:
                raise BridgeError("No additional event pages")
            result = {"events":[definition(role)]}
        elif method == "events/subscribe":
            result = events.subscribe(role, params)
        elif method == "events/unsubscribe":
            result = events.unsubscribe(role, params)
        else:
            return 404, rpc_error(request, -32601, "Method not found")
        result["resultType"] = "complete"
        result["_meta"] = {PREFIX+"serverInfo":{"name":"agent-babel","version":"0.4.0"}}
        return 200, {"jsonrpc":"2.0","id":request["id"],"result":result}
    except EventError as exc:
        return 200, rpc_error(request, exc.code, exc.message, exc.data)
    except BridgeError as exc:
        code = -32012 if exc.status == 403 else -32602
        return 200, rpc_error(request, code, str(exc))
