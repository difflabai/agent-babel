"""Reply capabilities for an existing private trusted-session backend.

This module does not enroll accounts, load credentials, or enable a backend.
Static directed grants remain unchanged when that backend is absent.
"""
from .core import BridgeError

EMBER = 'bits255.dots.ada_20261002'


def reply_routes(policy):
    leases = getattr(policy, 'session_leases', None)
    store = getattr(leases, 'store', None)
    roles = getattr(policy, 'session_dynamic_roles', ())
    if (not policy.multi_owner or not roles or store is None
            or getattr(store, 'sessions', None) is not leases
            or not callable(getattr(leases, 'row', None))):
        return set()
    try:
        policy.assert_active(EMBER)
    except BridgeError:
        return set()
    if policy.participants[EMBER]['owner'] != 'bits255':
        return set()
    routes = set()
    generations = getattr(policy, 'session_generations', {})
    with store.lock:
        for pid in roles:
            entry = policy.participants.get(pid)
            row = leases.row(pid)
            if (pid not in generations or not entry or entry['owner'] != 'bits255' or not row
                    or row['participant'] != pid or row['profile'] != 'ember_outbound'):
                continue
            cid = row['conversation']
            conversation = policy.conversations.get(cid)
            if (not conversation or conversation['state'] != 'active'
                    or set(conversation['participants']) != {pid, EMBER}
                    or (cid, pid, EMBER) not in policy.routes):
                continue
            try:
                policy.assert_active(pid)
                leases.assert_active(pid, generations[pid])
            except BridgeError:
                continue
            incoming = store.db.execute("""SELECT 1 FROM messages
                WHERE source=? AND recipient=? AND conversation_id=?
                AND source_owner='bits255' AND recipient_owner='bits255'
                AND provenance='mcp' AND status IN ('queued','acknowledged') LIMIT 1""",
                (pid, EMBER, cid)).fetchone()
            if incoming:
                routes.add((cid, EMBER, pid))
    return routes
