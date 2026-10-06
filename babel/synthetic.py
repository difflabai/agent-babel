"""Opt-in, RAM-only byte-bridge diagnostic for two existing principals.

Only the published synthetic fixture is accepted. Never opens user paths, makes
network requests, issues credentials, or persists payloads to the message DB.
"""
import base64
import binascii
import hashlib
import threading
import time
from .core import BridgeError, fields, identifier

SISTERS = frozenset(("bits255.dots.ada_20261002", "bits255.grokbot.grok_20261002"))
CONVERSATION = "bits255_ada_grok"
CHUNK_BYTES = 4096
MAX_BYTES = 1024 * 1024
TTL = 900
MAX_ACTIVE = 8
MAX_RECORDS = 512
FIXTURE = "babel-synthetic-v1"

def fixture(offset, length):
    return bytes(((offset + i) * 73 + 19) % 256 for i in range(length))

def digest(data):
    return hashlib.sha256(data).hexdigest()

TOOL = {
    "name": "synthetic_transfer",
    "description": "Temporary diagnostic: transfer ONLY babel-synthetic-v1 bytes between Ember and Ada. "
    "Byte i is (i*73+19)%256; maximum 1 MiB, chunks at most 4096 bytes. "
    "Begin with recipient, size, sha256 of the full fixture; put contiguous base64 chunks "
    "with offset and sha256; commit before get. Either endpoint may get committed chunks "
    "and delete. RAM-only, expires 900 seconds after begin; restart aborts transfers. "
    "Client tool arguments/results may be retained. Not a real-file sharing tool.",
    "inputSchema": {"type": "object", "additionalProperties": False,
        "required": ["action", "transfer_id"], "properties": {
            "action": {"type": "string", "enum": ["begin", "put", "commit", "get", "status", "delete"]},
            "transfer_id": {"type": "string", "minLength": 8, "maxLength": 128},
            "recipient": {"type": "string", "enum": sorted(SISTERS)},
            "size": {"type": "integer", "minimum": 1, "maximum": MAX_BYTES},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "offset": {"type": "integer", "minimum": 0, "maximum": MAX_BYTES},
            "data_base64": {"type": "string", "maxLength": 5464}}},
    "annotations": {"readOnlyHint": False, "destructiveHint": True,
                    "idempotentHint": True, "openWorldHint": False}}

class SyntheticTransfers:
    def __init__(self, clock=time.time):
        self.clock = clock
        self.lock = threading.RLock()
        self.records = {}

    def expire(self):
        with self.lock:
            now = self.clock()
            for record in self.records.values():
                if record["expires"] <= now and record["state"] not in ("expired", "deleted"):
                    record["data"] = b""
                    record["state"] = "expired"

    @staticmethod
    def available(scoped):
        return scoped.policy.multi_owner and scoped.role in SISTERS

    @staticmethod
    def summary(record):
        return {key: record[key] for key in ("transfer_id", "source", "recipient", "size",
                    "sha256", "expires", "state")} | {"received_bytes": len(record["data"]),
                    "fixture": FIXTURE, "chunk_bytes": CHUNK_BYTES}

    def call(self, scoped, args):
        if not self.available(scoped):
            raise BridgeError("Unknown tool", 403)
        scoped.guard()
        fields(args, ("action", "transfer_id", "recipient", "size", "sha256", "offset", "data_base64"),
               ("action", "transfer_id"))
        action, transfer_id = args["action"], identifier(args["transfer_id"])
        if action not in ("begin", "put", "commit", "get", "status", "delete"):
            raise BridgeError("Unknown synthetic action")
        required = {"begin": ("recipient", "size", "sha256"),
                    "put": ("offset", "sha256", "data_base64"), "get": ("offset",)}.get(action, ())
        fields(args, ("action", "transfer_id") + required, ("action", "transfer_id") + required)
        peer = next(role for role in SISTERS if role != scoped.role)
        scoped.policy.assert_route(CONVERSATION, scoped.role, peer)
        scoped.policy.assert_route(CONVERSATION, peer, scoped.role)
        with self.lock:
            self.expire()
            record = self.records.get(transfer_id)
            if action == "begin":
                size = args["size"]
                if args["recipient"] != peer or type(size) is not int or not 1 <= size <= MAX_BYTES:
                    raise BridgeError("Invalid synthetic recipient or size")
                expected_hash = digest(fixture(0, size))
                if args["sha256"] != expected_hash:
                    raise BridgeError("Manifest must match the published synthetic fixture")
                if record:
                    if record["source"] != scoped.role or record["recipient"] != peer:
                        raise BridgeError("Transfer unavailable", 404)
                    if record["state"] in ("expired", "deleted"):
                        raise BridgeError("Transfer expired or deleted; use a new ID", 410)
                    if record["size"] != size or record["sha256"] != expected_hash:
                        raise BridgeError("Transfer ID conflicts with its manifest", 409)
                    return self.summary(record)
                active = sum(r["state"] not in ("expired", "deleted") for r in self.records.values())
                if active >= MAX_ACTIVE or len(self.records) >= MAX_RECORDS:
                    raise BridgeError("Synthetic trial capacity reached", 429)
                record = {"transfer_id": transfer_id, "source": scoped.role, "recipient": peer,
                          "size": size, "sha256": expected_hash, "expires": self.clock() + TTL,
                          "state": "uploading", "data": b""}
                self.records[transfer_id] = record
            else:
                if not record or scoped.role not in (record["source"], record["recipient"]):
                    raise BridgeError("Transfer unavailable", 404)
                if action == "delete":
                    record["data"] = b""
                    record["state"] = "deleted"
                    return self.summary(record)
                if record["state"] in ("expired", "deleted"):
                    raise BridgeError("Transfer expired or deleted", 410)
                if action in ("put", "commit") and scoped.role != record["source"]:
                    raise BridgeError("Only the source may upload or commit", 403)
                if action in ("put", "get"):
                    offset = args["offset"]
                    if type(offset) is not int or not 0 <= offset < record["size"] or offset % CHUNK_BYTES:
                        raise BridgeError("Invalid chunk offset")
                if action == "put":
                    encoded = args["data_base64"]
                    if not isinstance(encoded, str) or len(encoded) > 5464:
                        raise BridgeError("Invalid base64 chunk")
                    try:
                        chunk = base64.b64decode(encoded, validate=True)
                    except (ValueError, binascii.Error):
                        raise BridgeError("Invalid base64 chunk") from None
                    length = min(CHUNK_BYTES, record["size"] - offset)
                    if len(chunk) != length or args["sha256"] != digest(chunk) or chunk != fixture(offset, length):
                        raise BridgeError("Chunk length, digest or synthetic bytes mismatch")
                    received = len(record["data"])
                    if offset < received:
                        if record["data"][offset:offset + length] != chunk:
                            raise BridgeError("Conflicting retry", 409)
                    elif record["state"] != "uploading" or offset != received:
                        raise BridgeError("Noncontiguous or conflicting offset", 409)
                    else:
                        record["data"] += chunk
                elif action == "commit":
                    if len(record["data"]) != record["size"] or digest(record["data"]) != record["sha256"]:
                        raise BridgeError("Incomplete or truncated transfer", 409)
                    record["state"] = "committed"
                elif action == "get":
                    if record["state"] != "committed":
                        raise BridgeError("Transfer must be committed before download", 409)
                    chunk = record["data"][offset:offset + CHUNK_BYTES]
                    return {"transfer_id": transfer_id, "offset": offset, "length": len(chunk),
                            "sha256": digest(chunk), "data_base64": base64.b64encode(chunk).decode("ascii"),
                            "total_size": record["size"], "file_sha256": record["sha256"]}
            return self.summary(record)
