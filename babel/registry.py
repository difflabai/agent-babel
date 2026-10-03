"""Durable identity tombstones and retired credential digests; bridge metadata only."""
import time
from .participants import digest
from .core import BridgeError

def synchronize(store, policy):
    if not policy.multi_owner:
        return
    now=time.time()
    with store.transaction():
        from .machines import synchronize as synchronize_machines
        synchronize_machines(store,policy)
        previous={r["id"]:dict(r) for r in store.db.execute("SELECT * FROM participant_bindings")}
        for pair,pid in getattr(policy,"bindings",{}).items():
            fingerprint=digest([policy.oauth["issuer"],*pair])
            by_principal=store.db.execute("SELECT * FROM oauth_bindings WHERE principal_digest=?",(fingerprint,)).fetchone()
            by_instance=store.db.execute("SELECT * FROM oauth_bindings WHERE participant=?",(pid,)).fetchone()
            if (by_principal and by_principal["participant"]!=pid) or (by_instance and by_instance["principal_digest"]!=fingerprint):
                raise BridgeError("OAuth principal and instance bindings cannot be recycled or reassigned")
            store.db.execute("INSERT OR IGNORE INTO oauth_bindings VALUES(?,?)",(fingerprint,pid))
        for pid, entry in policy.participants.items():
            old=previous.get(pid)
            binding=(entry["owner"],entry["client"],entry["session"])
            if old and tuple(old[k] for k in ("owner","client","session"))!=binding:
                raise BridgeError("Participant IDs cannot be reassigned")
            state=entry["state"]
            if state=="active" and entry["expires"] is not None and entry["expires"]<=now: state="closed"
            if old:
                if old["state"] in ("closed","revoked") and state not in ("closed","revoked"):
                    raise BridgeError("Closed or revoked participant IDs cannot be reused")
                if old["activated_at"] and entry["activated_at"]!=old["activated_at"]:
                    raise BridgeError("Activation time is immutable; use a fresh instance ID")
            static=policy.credential_digests.get(pid)
            if static:
                if store.db.execute("SELECT 1 FROM machine_credential_bindings WHERE digest=?", (static,)).fetchone():
                    raise BridgeError("A machine credential cannot become a participant credential")
                known=store.db.execute("SELECT * FROM credential_bindings WHERE digest=?",(static,)).fetchone()
                if known and (known["participant"]!=pid or (known["retired"] and state not in ("closed","revoked"))):
                    raise BridgeError("A retired or another participant's credential cannot be reused")
            if old and old["static_digest"] and old["static_digest"]!=static:
                store.db.execute("UPDATE credential_bindings SET retired=1 WHERE digest=?",(old["static_digest"],))
            if static:
                store.db.execute("INSERT OR IGNORE INTO credential_bindings VALUES(?,?,0)",(static,pid))
            store.db.execute("""INSERT INTO participant_bindings
                (id,owner,client,session,state,activated_at,static_digest) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET state=excluded.state,activated_at=excluded.activated_at,static_digest=excluded.static_digest""",
                (pid,*binding,state,entry["activated_at"],static))
            if state in ("closed","revoked"):
                # A removed identity leaves an irreversible tombstone.
                if static: store.db.execute("UPDATE credential_bindings SET retired=1 WHERE digest=?",(static,))
        for pid in previous.keys()-policy.participants.keys():
            store.db.execute("UPDATE participant_bindings SET state='revoked' WHERE id=?",(pid,))
            store.db.execute("UPDATE credential_bindings SET retired=1 WHERE participant=?",(pid,))
        # Authorization fingerprints also include conversation grants. Any policy
        # reduction stops pending notifications; new grants require resubscription.
        for sub in store.db.execute("SELECT id,role,auth_digest FROM subscriptions WHERE active=1").fetchall():
            current=policy.agents.get(sub["role"])
            try: policy.assert_active(sub["role"])
            except BridgeError: current=None
            if not current or current[0]!=sub["auth_digest"]:
                store.db.execute("UPDATE subscriptions SET active=0,secret='',old_secret=NULL WHERE id=?",(sub["id"],))
                store.db.execute("UPDATE outbox SET status='canceled',last_error='access_revoked' WHERE subscription_id=? AND status IN ('pending','leased')",(sub["id"],))
