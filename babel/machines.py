"""Opt-in machine authentication, with operator-pinned session selectors.

A native session identifier is attribution within an authenticated machine. It
is not proof of a separate process or person. No public enrollment is provided.
"""
import hashlib
import secrets
from .core import BridgeError, fields, identifier
from .participants import COMPONENT

WORKER_CLIENTS = frozenset(("codex", "claude", "cursor", "opencode", "grokbot"))


def configure(policy, config):
    from .auth import DIGEST
    machines = config.get("machines", {})
    bindings = config.get("machine_sessions", {})
    if not isinstance(machines, dict) or len(machines) > 32:
        raise BridgeError("At most 32 explicit machines may be configured")
    if not isinstance(bindings, dict) or len(bindings) > 64:
        raise BridgeError("At most 64 explicit machine sessions may be configured")
    seen = set()
    for mid, entry in machines.items():
        if not isinstance(mid, str) or not COMPONENT.fullmatch(mid):
            raise BridgeError("Invalid machine ID")
        fields(entry, ("owner", "state", "sha256", "coordinators"),
               ("owner", "state", "sha256", "coordinators"))
        if (not isinstance(entry["owner"], str) or entry["owner"] not in policy.owners
                or entry["state"] not in ("active", "revoked")):
            raise BridgeError("Invalid machine owner or state")
        value = entry["sha256"]
        if (not isinstance(value, str) or not DIGEST.fullmatch(value)
                or value == "0" * 64 or value in seen):
            raise BridgeError("Machines require distinct non-placeholder credential digests")
        seen.add(value)
        hubs = entry["coordinators"]
        if (not isinstance(hubs, list) or len(hubs) != 2
                or any(not isinstance(h, str) or h not in config["participants"] for h in hubs)
                or len(set(hubs)) != 2 or any(h in bindings for h in hubs)):
            raise BridgeError("Machines require two explicitly configured non-worker coordinators")
    native = set()
    for pid, binding in bindings.items():
        fields(binding, ("machine", "native_session"), ("machine", "native_session"))
        mid = binding["machine"]
        entry = config["participants"].get(pid)
        if (not isinstance(mid, str) or mid not in machines or not isinstance(entry, dict)
                or not isinstance(entry.get("client"), str) or entry["client"] not in WORKER_CLIENTS
                or entry.get("owner") != machines[mid]["owner"]):
            raise BridgeError("Machine session must belong to its configured worker owner")
        identifier(binding["native_session"])
        key = (mid, entry["client"], binding["native_session"])
        if key in native:
            raise BridgeError("A machine/client native session cannot select multiple mailboxes")
        native.add(key)
    policy.machines = machines
    policy.machine_sessions = bindings
    return seen


def validate_routes(policy):
    for cid, source, recipient in policy.routes:
        for worker, peer in ((source, recipient), (recipient, source)):
            binding = policy.machine_sessions.get(worker)
            if binding and peer not in policy.machines[binding["machine"]]["coordinators"]:
                raise BridgeError("Machine workers may communicate only with their configured coordinators")


def authenticate(policy, header, participant, native_session):
    from .auth import TOKEN
    if not isinstance(header, str) or not header.startswith("Bearer ") or not TOKEN.fullmatch(header[7:]):
        raise BridgeError("Invalid machine credential", 401)
    value = hashlib.sha256(header[7:].encode("ascii")).hexdigest()
    mid = next((m for m, e in policy.machines.items()
                if secrets.compare_digest(value, e["sha256"])), None)
    if mid is None:
        raise BridgeError("Invalid machine credential", 401)
    machine = policy.machines[mid]
    if machine["state"] != "active" or not policy.owners[machine["owner"]]["enabled"]:
        raise BridgeError("Machine access is unavailable", 403)
    binding = policy.machine_sessions.get(participant) if isinstance(participant, str) else None
    if (not binding or binding["machine"] != mid or not isinstance(native_session, str)
            or not secrets.compare_digest(native_session.encode(), binding["native_session"].encode())):
        raise BridgeError("Machine session is not authorized", 403)
    policy.assert_active(participant)
    policy.limit_request("machine:" + mid)
    policy.limit_request(participant)
    return participant


def synchronize(store, policy):
    """Called inside registry's transaction; all removal/rebinding is fenced."""
    previous = {r["id"]: dict(r) for r in store.db.execute("SELECT * FROM machine_bindings")}
    for mid, entry in policy.machines.items():
        old = previous.get(mid)
        if old and (old["owner"] != entry["owner"] or
                    old["state"] == "revoked" and entry["state"] != "revoked"):
            raise BridgeError("Machine identities cannot be reassigned or reopened")
        value = entry["sha256"]
        if store.db.execute("SELECT 1 FROM credential_bindings WHERE digest=?", (value,)).fetchone():
            raise BridgeError("A participant credential cannot become a machine credential")
        known = store.db.execute("SELECT * FROM machine_credential_bindings WHERE digest=?", (value,)).fetchone()
        if known and (known["machine"] != mid or known["retired"] and entry["state"] != "revoked"):
            raise BridgeError("Machine credentials cannot be recycled or reassigned")
        if old and old["static_digest"] != value:
            store.db.execute("UPDATE machine_credential_bindings SET retired=1 WHERE digest=?", (old["static_digest"],))
        store.db.execute("INSERT OR IGNORE INTO machine_credential_bindings VALUES(?,?,0)", (value, mid))
        store.db.execute("""INSERT INTO machine_bindings VALUES(?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET state=excluded.state,static_digest=excluded.static_digest""",
            (mid, entry["owner"], entry["state"], value))
        if entry["state"] == "revoked":
            store.db.execute("UPDATE machine_credential_bindings SET retired=1 WHERE machine=?", (mid,))
    for mid in previous.keys() - policy.machines.keys():
        store.db.execute("UPDATE machine_bindings SET state='revoked' WHERE id=?", (mid,))
        store.db.execute("UPDATE machine_credential_bindings SET retired=1 WHERE machine=?", (mid,))
    existing = {r["participant"]: dict(r) for r in store.db.execute("SELECT * FROM machine_session_bindings")}
    for pid, binding in policy.machine_sessions.items():
        entry = policy.participants[pid]
        identity = (binding["machine"], entry["client"], binding["native_session"])
        old = existing.get(pid)
        if old and (old["retired"] or tuple(old[k] for k in ("machine", "client", "native_session")) != identity):
            raise BridgeError("Machine session bindings cannot be recycled or reassigned")
        occupied = store.db.execute("""SELECT participant FROM machine_session_bindings
            WHERE machine=? AND client=? AND native_session=?""", identity).fetchone()
        if occupied and occupied["participant"] != pid:
            raise BridgeError("A native session cannot be moved to another mailbox")
        store.db.execute("INSERT OR IGNORE INTO machine_session_bindings VALUES(?,?,?,?,0)", (pid, *identity))
    for pid in existing.keys() - policy.machine_sessions.keys():
        store.db.execute("UPDATE machine_session_bindings SET retired=1 WHERE participant=?", (pid,))
