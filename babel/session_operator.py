"""Private operator command for schema-2 collector requests. No public RPC."""
from .auth import Policy
from .core import fields, BridgeError, Store
from .session_leases import SessionLeases, load_accounts, PEERS


def apply(store, config, policy, verified_peer, request):
    # verified_peer is supplied by the operator's pinned SSH transport. No peer
    # field is accepted from worker JSON; private CLI/operator can edit policy.
    fields(request,('schema_version','client','native_id','sha256','event_id','kind','existing_participant','observed_at'),
           ('schema_version','client','native_id','sha256','event_id','kind'))
    if type(request['schema_version']) is not int or request['schema_version']!=2:
        raise BridgeError('Expected trusted-session schema2')
    leases=store.sessions or SessionLeases(store,config)
    return leases.bootstrap(policy,peer=verified_peer,**{k:v for k,v in request.items() if k!='schema_version'})


def add_parser(modes):
    parser=modes.add_parser('trusted-session',help='PRIVATE trusted-account lifecycle operator; disabled unless configured')
    parser.add_argument('--accounts-file',required=True)
    parser.add_argument('--policy-file',required=True)
    parser.add_argument('--peer',required=True,choices=sorted(PEERS))
    parser.add_argument('--action',choices=('bootstrap','cleanup','revoke-account','revoke-session','adopt'),default='bootstrap')
    parser.add_argument('--participant')
    parser.add_argument('--native-id',help='Inventory-confirmed native ID or disclosed legacy account-local binding')
    parser.add_argument('--evidence',choices=('server_reports','rollout_grace'),default='server_reports')


def run(args):
    import json,sys
    store=Store()
    try:
        config=load_accounts(args.accounts_file)
        leases=SessionLeases(store,config)
        if args.action=='cleanup':return {'expired':leases.cleanup()}
        if args.action=='adopt':
            return leases.adopt(Policy.load(args.policy_file),peer=args.peer,participant=args.participant,native_id=args.native_id,evidence=args.evidence)
        if args.action=='revoke-account':
            leases.revoke(peer=args.peer);return {'revoked':True}
        if args.action=='revoke-session':
            row=leases.row(args.participant)
            if not row or row['peer']!=args.peer:raise BridgeError('Session is not owned by selected account',403)
            leases.revoke(participant=args.participant);return {'revoked':True}
        raw=sys.stdin.buffer.read(8193)
        if len(raw)>8192:raise BridgeError('Lifecycle request too large')
        try:request=json.loads(raw)
        except (ValueError,UnicodeError):raise BridgeError('Invalid lifecycle request') from None
        return apply(store,config,Policy.load(args.policy_file),args.peer,request)
    finally:store.close()
