import argparse
import os
from .core import AGENTS, BridgeError, Store
from .mcp import stdio
from .server import run

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Agent Babel — approved durable agent messages")
    modes = parser.add_subparsers(dest="mode", required=True)
    ui = modes.add_parser("serve", help="Start loopback operator UI and trusted local MCP")
    ui.add_argument("--port", type=int, default=8765)
    ui.add_argument("--container", action="store_true", help="Isolated Docker operator with loopback-published port")
    mcp = modes.add_parser("mcp", help="Start trusted local tools-only stdio MCP")
    mcp.add_argument("--agent", choices=AGENTS, required=True)
    gateway = modes.add_parser("gateway", help="Authenticated MCP behind a trusted HTTPS proxy")
    gateway.add_argument("--port", type=int, default=8080)
    gateway.add_argument("--container", action="store_true", help="Listen on private Docker network")
    modes.add_parser("wake", help="Run explicitly configured HTTPS notification worker")
    modes.add_parser("backup", help="Online SQLite backup inside configured bridge data/backups")
    from .enrollment import add_parser
    add_parser(modes)
    args = parser.parse_args()
    if hasattr(args, "port") and not 0 <= args.port <= 65535:
        parser.error("--port must be 0–65535 (0 selects a free port)")
    try:
        if args.mode == "policy":
            from .enrollment import edit
            options={k:v for k,v in vars(args).items() if k not in ("mode","file","policy_action")}
            edit(args.file,args.policy_action,**options)
            print("Participant policy structurally validated." if args.policy_action=="validate" else "Explicit operator policy edit saved; no credentials issued or messages sent.",flush=True)
        elif args.mode == "serve":
            run(args.port, container=args.container)
        elif args.mode == "gateway":
            from .gateway import run_gateway
            auth_file = os.environ.get("BABEL_AUTH_FILE")
            origin = os.environ.get("BABEL_PUBLIC_ORIGIN")
            if not auth_file or not origin:
                raise BridgeError("Gateway requires BABEL_AUTH_FILE and BABEL_PUBLIC_ORIGIN")
            run_gateway(args.port, auth_file, origin, host="0.0.0.0" if args.container else "127.0.0.1", wake_file=os.environ.get("BABEL_WAKE_FILE"))
        elif args.mode == "wake":
            import time
            from .auth import Policy
            from .events import EventService
            from .wake import WakeConfig
            auth_file, wake_file = os.environ.get("BABEL_AUTH_FILE"), os.environ.get("BABEL_WAKE_FILE")
            if not auth_file or not wake_file:
                raise BridgeError("Wake worker requires explicit auth and wake configuration")
            config = WakeConfig.load(wake_file)
            if not config.enabled:
                raise BridgeError("Wake delivery is disabled")
            store = Store()
            try:
                while True:
                    # Recheck recipient access and callback allowlists for every attempt.
                    config = WakeConfig.load(wake_file)
                    service = EventService(store, Policy.load(auth_file), config)
                    service.process_one()
                    time.sleep(1)  # Max 60 notification attempts/minute per worker; no autonomous messages.
            except KeyboardInterrupt:
                pass
            finally:
                store.close()
        elif args.mode == "backup":
            store = Store()
            try:
                print(store.backup(), flush=True)
            finally:
                store.close()
        else:
            stdio(args.agent)
    except (BridgeError, OSError) as exc:
        # Configuration errors never print config bodies, headers or credentials.
        parser.exit(2, "Babel could not start: " + (str(exc) if isinstance(exc, BridgeError) else "storage or configuration unavailable") + "\n")

if __name__ == "__main__":
    main()
