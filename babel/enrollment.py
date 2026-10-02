"""Host-only, explicit enrollment edits. Never creates or sends credentials."""
import argparse
import copy
import fcntl
import json
import os
from pathlib import Path
import tempfile
import time
from .auth import Policy
from .core import BridgeError, fields, identifier
from .participants import COMPONENT, CLIENTS, lifetime_limit

def validate(config):
    if not isinstance(config,dict) or config.get("schema_version")!=3:
        raise BridgeError("Enrollment commands require schema 3; legacy configuration is never rewritten")
    base={k:v for k,v in config.items() if k!="oauth"}
    oauth=config.get("oauth")
    roles=set()
    if oauth is not None:
        fields(oauth,("issuer","resource","jwks_file","principals"),("issuer","resource","jwks_file","principals"))
        principals=oauth["principals"]
        if not isinstance(principals,dict): raise BridgeError("Invalid OAuth principal configuration")
        seen=set()
        for pid,value in principals.items():
            if pid not in base["participants"]: raise BridgeError("OAuth participant is not configured")
            fields(value,("subject","client_id"),("subject","client_id"))
            if any(not isinstance(value[k],str) or not value[k] or "<" in value[k] for k in ("subject","client_id")):
                raise BridgeError("OAuth requires explicit actual provider principals")
            pair=(value["subject"],value["client_id"])
            if pair in seen: raise BridgeError("OAuth principal pairs cannot identify multiple instances")
            seen.add(pair); roles.add(pid)
    Policy(base,oauth_roles=roles)  # Structural enrollment checks; runtime also verifies issuer/JWKS.

def change(config, action, **args):
    result=copy.deepcopy(config)
    if action=="owner":
        owner=args["owner"]
        if not COMPONENT.fullmatch(owner): raise BridgeError("Invalid owner ID")
        if owner in result["owners"]: raise BridgeError("Owner already exists")
        result["owners"][owner]={"enabled":True}
    elif action=="invite":
        owner,client,session=args["owner"],args["client"],args["session"]
        if owner not in result["owners"] or client not in CLIENTS: raise BridgeError("Configure owner and supported client label first")
        pid=owner+"."+client+"."+session
        if pid in result["participants"]: raise BridgeError("Instance already exists; use a fresh session ID")
        expires=args["expires"]; now=int(time.time())
        if type(expires) is not int or not now<expires<=now+lifetime_limit(client):
            raise BridgeError("Invitation expiry must be future and within the client lifetime limit")
        result["participants"][pid]={"owner":owner,"client":client,"session":session,"state":"invited",
                                    "accepted":False,"expires":expires,"activated_at":0}
    elif action=="expiry":
        entry=result["participants"].get(args["participant"])
        now=int(time.time()); expires=args["expires"]
        if not entry or entry["state"]!="invited" or not now<expires<=now+lifetime_limit(entry["client"]):
            raise BridgeError("Only a pending invitation may receive a new bounded expiry")
        entry["expires"]=expires
    elif action=="activate":
        entry=result["participants"].get(args["participant"])
        if not entry or entry["state"]!="invited" or not args.get("accepted"):
            raise BridgeError("Activation requires an invited instance and explicit owner-acceptance confirmation")
        entry["accepted"]=True; entry["state"]="active"; entry["activated_at"]=int(time.time())+1
        if args.get("sha256"): entry["sha256"]=args["sha256"]
    elif action in ("close","revoke"):
        entry=result["participants"].get(args["participant"])
        if not entry: raise BridgeError("Participant is not configured")
        entry["state"]="closed" if action=="close" else "revoked"
    elif action=="revoke-owner":
        owner=args["owner"]
        if owner not in result["owners"]: raise BridgeError("Owner is not configured")
        result["owners"][owner]["enabled"]=False
        for entry in result["participants"].values():
            if entry["owner"]==owner: entry["state"]="revoked"
    elif action=="conversation":
        cid=identifier(args["conversation"])
        if cid in result["conversations"]: raise BridgeError("Conversation already exists")
        result["conversations"][cid]={"state":"active","participants":args["members"],"routes":[]}
    elif action in ("grant","ungrant"):
        conversation=result["conversations"].get(args["conversation"])
        if not conversation or conversation["state"]!="active": raise BridgeError("Conversation is unavailable")
        route={"sender":args["sender"],"recipient":args["recipient"]}
        if action=="grant" and route not in conversation["routes"]: conversation["routes"].append(route)
        if action=="ungrant": conversation["routes"]=[r for r in conversation["routes"] if r!=route]
    elif action=="close-conversation":
        conversation=result["conversations"].get(args["conversation"])
        if not conversation: raise BridgeError("Conversation is unavailable")
        conversation["state"]="closed"
    else: raise BridgeError("Unsupported policy operation")
    validate(result)
    return result

def edit(filename, action, **args):
    path=Path(filename)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>65536:
        raise BridgeError("Policy must be an existing regular private file of at most 64 KiB")
    if action=="validate":
        try: validate(json.loads(path.read_bytes()))
        except (ValueError,TypeError,KeyError): raise BridgeError("Invalid participant policy") from None
        return
    lock=Path(str(path)+".lock")
    fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    temporary=None
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        original=path.read_bytes()
        config=json.loads(original); validate(config)
        if action=="validate": return
        result=change(config,action,**args)
        raw=(json.dumps(result,indent=2)+"\n").encode()
        if len(raw)>65536: raise BridgeError("Policy capacity reached")
        if path.is_symlink() or path.read_bytes()!=original: raise BridgeError("Policy changed concurrently; retry after review")
        stat=path.stat()
        handle,tempname=tempfile.mkstemp(prefix=".babel-policy-",dir=path.parent)
        temporary=Path(tempname)
        with os.fdopen(handle,"wb") as output:
            os.fchmod(output.fileno(),stat.st_mode & 0o777)
            if stat.st_uid!=os.geteuid() or stat.st_gid!=os.getegid(): os.fchown(output.fileno(),stat.st_uid,stat.st_gid)
            output.write(raw); output.flush(); os.fsync(output.fileno())
        if path.is_symlink() or path.read_bytes()!=original: raise BridgeError("Policy changed concurrently; retry after review")
        os.replace(temporary,path)
        directory=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    except (ValueError,TypeError,KeyError):
        raise BridgeError("Invalid participant policy") from None
    finally:
        if temporary and temporary.exists(): temporary.unlink()
        os.close(fd)

def add_parser(modes):
    parser=modes.add_parser("policy",help="Host-only participant enrollment; never issues or sends credentials")
    parser.add_argument("--file",required=True,help="Explicit private schema 3 policy file")
    actions=parser.add_subparsers(dest="policy_action",required=True)
    actions.add_parser("validate")
    owner=actions.add_parser("owner"); owner.add_argument("--owner",required=True)
    invite=actions.add_parser("invite")
    for name in ("owner","session"): invite.add_argument("--"+name,required=True)
    invite.add_argument("--client",required=True,choices=CLIENTS); invite.add_argument("--expires",required=True,type=int)
    expiry=actions.add_parser("expiry"); expiry.add_argument("--participant",required=True); expiry.add_argument("--expires",required=True,type=int)
    activate=actions.add_parser("activate"); activate.add_argument("--participant",required=True)
    activate.add_argument("--accepted",action="store_true",required=True); activate.add_argument("--sha256")
    for name in ("close","revoke"):
        actions.add_parser(name).add_argument("--participant",required=True)
    actions.add_parser("revoke-owner").add_argument("--owner",required=True)
    conv=actions.add_parser("conversation"); conv.add_argument("--conversation",required=True); conv.add_argument("--members",nargs="+",required=True)
    for name in ("grant","ungrant"):
        grant=actions.add_parser(name)
        for field in ("conversation","sender","recipient"): grant.add_argument("--"+field,required=True)
    actions.add_parser("close-conversation").add_argument("--conversation",required=True)
