"""Operator-managed participant policy. No enrollment endpoint is public."""
import hashlib
import json
import re
import time
from .core import AGENTS, BridgeError, fields

COMPONENT = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
CLIENTS = ("dots","grokbot","codex","cursor","claude","opencode","muse")
INTERACTIVE_CLIENTS = frozenset(("codex", "cursor", "claude", "opencode"))
PARTICIPANT = re.compile(r"[a-z][a-z0-9_-]{0,31}\." + "(?:" + "|".join(CLIENTS) + r")\.[a-z][a-z0-9_-]{0,47}\Z")
STATES = ("invited","active","closed","revoked")

def lifetime_limit(client):
    return 86400 if client in INTERACTIVE_CLIENTS else 2592000

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def configure(policy, config, oauth_roles):
    from .auth import DIGEST
    fields(config,("schema_version","owners","participants","conversations"),
           ("schema_version","owners","participants","conversations"))
    owners=config["owners"]; participants=config["participants"]; conversations=config["conversations"]
    if not isinstance(owners,dict) or not 1<=len(owners)<=32:
        raise BridgeError("Policy needs 1–32 explicitly configured owners")
    for owner, entry in owners.items():
        if not COMPONENT.fullmatch(owner): raise BridgeError("Invalid owner ID")
        fields(entry,("enabled",),("enabled",))
        if type(entry["enabled"]) is not bool: raise BridgeError("Owner enabled must be boolean")
    if not isinstance(participants,dict) or not 1<=len(participants)<=64:
        raise BridgeError("Policy needs 1–64 explicitly configured participants")
    seen=set(); policy.credential_digests={}
    for pid, entry in participants.items():
        if not PARTICIPANT.fullmatch(pid): raise BridgeError("Participant ID must be owner.client.instance")
        fields(entry,("owner","client","session","state","accepted","expires","activated_at","sha256"),
               ("owner","client","session","state","accepted","expires","activated_at"))
        if (entry["owner"] not in owners or entry["client"] not in CLIENTS
                or pid != entry["owner"]+"."+entry["client"]+"."+entry["session"]):
            raise BridgeError("Participant identity must match its explicit owner, client and session")
        if entry["state"] not in STATES or type(entry["accepted"]) is not bool:
            raise BridgeError("Invalid participant lifecycle")
        expires=entry["expires"]
        if (expires is not None and type(expires) is not int) or type(entry["activated_at"]) is not int:
            raise BridgeError("Participant expiry must be null or Unix integer seconds")
        if entry["state"]=="active" and (not entry["accepted"] or entry["activated_at"]<=0
                or (expires is not None and (expires<=entry["activated_at"]
                    or expires-entry["activated_at"]>lifetime_limit(entry["client"])))):
            raise BridgeError("Active enrollment requires owner acceptance and a valid optional session lifetime")
        value=entry.get("sha256")
        if value is not None:
            if not isinstance(value,str) or not DIGEST.fullmatch(value) or value=="0"*64 or value in seen:
                raise BridgeError("Participant credentials must be distinct non-placeholder digests")
            seen.add(value); policy.credential_digests[pid]=value
        elif entry["state"]=="active" and pid not in oauth_roles:
            raise BridgeError("Active participant needs a separately provisioned credential or OAuth binding")
    if not isinstance(conversations,dict) or len(conversations)>64:
        raise BridgeError("At most 64 conversations may be configured")
    routes=set()
    for cid, entry in conversations.items():
        from .core import identifier
        identifier(cid)
        fields(entry,("state","participants","routes"),("state","participants","routes"))
        members=entry["participants"]
        if (entry["state"] not in ("active","closed","revoked") or not isinstance(members,list)
                or not 2<=len(members)<=16 or any(not isinstance(x,str) or x not in participants for x in members)
                or len(set(members))!=len(members) or not isinstance(entry["routes"],list) or len(entry["routes"])>32):
            raise BridgeError("Invalid conversation membership or lifecycle")
        local=set()
        for route in entry["routes"]:
            fields(route,("sender","recipient"),("sender","recipient"))
            pair=(route["sender"],route["recipient"])
            if pair[0] not in members or pair[1] not in members or pair[0]==pair[1] or pair in local:
                raise BridgeError("Routes require distinct explicit conversation members")
            local.add(pair)
            if entry["state"]=="active": routes.add((cid,*pair))
    if len(routes)>256: raise BridgeError("At most 256 explicit routes may be configured")
    policy.multi_owner=True; policy.owners=owners; policy.participants=participants
    policy.conversations=conversations; policy.routes=frozenset(routes); policy.agents={}
    for pid, entry in participants.items():
        permissions=sorted(r for r in routes if pid in r[1:])
        policy.agents[pid]=(digest([entry,owners[entry["owner"]],permissions]),
                            frozenset(r[2] for r in routes if r[1]==pid))
