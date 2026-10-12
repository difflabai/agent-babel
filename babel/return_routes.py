"""Explicit host-only reverse routes for existing authenticated mailboxes.

No enrollment, credentials, native adapters, activity renewal or wake opt-in.
Append-only decisions live outside the static policy and are checked on every use.
"""
import copy
import hashlib
import json
import time
from pathlib import Path
from .core import BridgeError, Store, agent, identifier
from .auth import Policy

MAX_DECISIONS = 8192
MAX_ROUTES = 256


class ReturnRoutes:
    def __init__(self, store):
        self.store = store
        with store.transaction():
            store.db.execute('''CREATE TABLE IF NOT EXISTS return_route_decisions (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT UNIQUE NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('grant','revoke')),
                conversation TEXT NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL,
                owner TEXT NOT NULL, peer TEXT, native_id TEXT, generation INTEGER,
                expires REAL, created REAL NOT NULL)''')
            store.db.execute('''CREATE INDEX IF NOT EXISTS return_route_latest
                ON return_route_decisions(conversation,sender,recipient,seq)''')
            # One withdrawal slot per grant, independent of grant-audit capacity.
            # Both logs are immutable. FK + PK bound this table to <=8192 rows.
            store.db.execute('''CREATE TABLE IF NOT EXISTS return_route_withdrawals (
                grant_seq INTEGER PRIMARY KEY REFERENCES return_route_decisions(seq),
                operation_id TEXT UNIQUE NOT NULL, created REAL NOT NULL)''')

    @staticmethod
    def strip(policy):
        return getattr(policy, 'return_route_base', policy)

    def latest(self, route):
        row = self.store.db.execute('''SELECT d.*,w.created AS withdrawn_at FROM return_route_decisions d
            LEFT JOIN return_route_withdrawals w ON w.grant_seq=d.seq
            WHERE conversation=? AND sender=? AND recipient=? ORDER BY d.seq DESC LIMIT 1''', route).fetchone()
        return dict(row) if row else None

    def scope(self, policy, route, peer=None, native_id=None):
        policy = self.strip(policy)
        conversation, sender, recipient = route
        identifier(conversation); agent(sender); agent(recipient)
        if not policy.multi_owner:
            raise BridgeError('Return routes require participant policy')
        # Require an original outgoing grant, never another return-route overlay.
        policy.assert_route(conversation, recipient, sender)
        owner = policy.participants[sender]['owner']
        if policy.participants[recipient]['owner'] != owner:
            raise BridgeError('Return routes cannot cross owners', 403)
        lease = self.store.trusted_session_row(recipient)
        if lease:
            if not self.store.sessions:
                raise BridgeError('Trusted-session lifecycle configuration is required', 403)
            self.store.sessions.assert_active(recipient, lease['generation'])
            if (peer, native_id) != (lease['peer'], lease['native_id']):
                raise BridgeError('Return route does not match the owned native session', 403)
            if lease['profile'] == 'ember_outbound':
                key = hashlib.sha256(json.dumps([peer, lease['client'], native_id], separators=(',', ':')).encode()).hexdigest()[:32]
                if (owner != 'bits255' or recipient != 'bits255.'+lease['client']+'.auto_'+key
                        or conversation != 'report_auto_'+key+'_ember'):
                    raise BridgeError('Automatic identity or conversation binding mismatch', 403)
                if recipient in policy.participants and recipient not in policy.session_dynamic_roles:
                    raise BridgeError('Automatic identity conflicts with static policy', 409)
            elif lease['profile'] != 'existing_grants':
                raise BridgeError('Unsupported trusted-session profile', 403)
            return {'owner': owner, 'peer': peer, 'native_id': native_id,
                    'generation': lease['generation'], 'expires': lease['deadline']}
        if peer is not None or native_id is not None:
            raise BridgeError('Static mailbox has no native session binding', 403)
        return {'owner': owner, 'peer': None, 'native_id': None,
                'generation': None, 'expires': None}

    def usable(self, policy, decision):
        if not decision or decision['action'] != 'grant' or decision.get('withdrawn_at') is not None:
            raise BridgeError('Explicit return route is unavailable', 403)
        route = (decision['conversation'], decision['sender'], decision['recipient'])
        scope = self.scope(policy, route, decision['peer'], decision['native_id'])
        if any(scope[k] != decision[k] for k in ('owner','peer','native_id','generation')):
            raise BridgeError('Return-route identity or credential generation changed', 403)
        if decision['expires'] is not None:
            now = self.store.sessions.clock()
            if now >= decision['expires']:
                raise BridgeError('Approved return-route lease expired', 403)
        return route

    @staticmethod
    def capacity(policy, route):
        if route not in policy.routes:
            if len(policy.routes) >= MAX_ROUTES:
                raise BridgeError('Return-route grant capacity reached', 429)
            if sum(r[0] == route[0] for r in policy.routes) >= 32:
                raise BridgeError('Conversation route capacity reached', 429)

    def withdraw(self, *, operation_id, grant_operation_id, route, peer, native_id,
                 expected_generation, dry_run):
        """Withdraw an exact stored grant even after its admission scope disappears.

        This PRIVATE reduction never uses current policy/account/activity as
        authority, and cannot accidentally target a subsequent replacement grant.
        The caller must supply the original grant's exact identity/context scope.
        """
        identifier(grant_operation_id)
        grant = self.store.db.execute('SELECT * FROM return_route_decisions WHERE operation_id=?',
                                      (grant_operation_id,)).fetchone()
        if not grant or grant['action'] != 'grant':
            raise BridgeError('Original grant decision is unavailable', 404)
        if (grant['conversation'], grant['sender'], grant['recipient'], grant['peer'], grant['native_id']) != (*route, peer, native_id):
            raise BridgeError('Withdrawal does not match the stored exact grant scope', 403)
        if (grant['sender'].split('.')[0] != grant['owner'] or grant['recipient'].split('.')[0] != grant['owner']):
            raise BridgeError('Stored grant ownership binding is unavailable', 403)
        if expected_generation is not None and grant['generation'] != expected_generation:
            raise BridgeError('Expected original grant generation does not match', 409)
        if self.store.db.execute('SELECT 1 FROM return_route_decisions WHERE operation_id=?', (operation_id,)).fetchone():
            raise BridgeError('Operator operation ID belongs to another decision', 409)
        seen = self.store.db.execute('SELECT * FROM return_route_withdrawals WHERE operation_id=?', (operation_id,)).fetchone()
        existing = self.store.db.execute('SELECT * FROM return_route_withdrawals WHERE grant_seq=?', (grant['seq'],)).fetchone()
        if seen and seen['grant_seq'] != grant['seq']:
            raise BridgeError('Operator operation ID belongs to another withdrawal', 409)
        if existing and not seen:
            raise BridgeError('Grant already withdrawn; retry its original withdrawal ID', 409)
        created = seen['created'] if seen else time.time()
        if not dry_run and not seen:
            self.store.db.execute('INSERT INTO return_route_withdrawals VALUES(?,?,?)',
                                  (grant['seq'], operation_id, created))
        result = dict(grant)
        result.update(action='revoke', operation_id=operation_id, grant_operation_id=grant_operation_id,
                      created=created, changed=not dry_run and not bool(seen), dry_run=dry_run,
                      withdrawn=bool(seen) or not dry_run, effective=None)
        return result

    def decide(self, policy, *, action, operation_id, sender, recipient, conversation,
               peer=None, native_id=None, expected_generation=None, dry_run=False, grant_operation_id=None):
        if action not in ('grant','revoke'):
            raise BridgeError('Unsupported return-route action')
        identifier(operation_id)
        route = (conversation, sender, recipient)
        identifier(conversation); agent(sender); agent(recipient)
        if action == 'revoke' and not grant_operation_id:
            raise BridgeError('Withdrawal requires the original grant operation ID')
        if action == 'grant' and grant_operation_id is not None:
            raise BridgeError('Original grant operation ID is only for withdrawal')
        with self.store.transaction():
            if action == 'revoke':
                return self.withdraw(operation_id=operation_id, grant_operation_id=grant_operation_id,
                    route=route, peer=peer, native_id=native_id,
                    expected_generation=expected_generation, dry_run=dry_run)
            scope = self.scope(policy, route, peer, native_id)
            if expected_generation is not None and scope['generation'] != expected_generation:
                raise BridgeError('Expected credential generation does not match', 409)
            seen = self.store.db.execute('SELECT * FROM return_route_decisions WHERE operation_id=?', (operation_id,)).fetchone()
            if self.store.db.execute('SELECT 1 FROM return_route_withdrawals WHERE operation_id=?', (operation_id,)).fetchone():
                raise BridgeError('Operator operation ID belongs to another withdrawal', 409)
            if seen:
                if (seen['action'], seen['conversation'], seen['sender'], seen['recipient'], seen['owner'],
                        seen['peer'], seen['native_id'], seen['generation']) != (
                        action, *route, scope['owner'], peer, native_id, scope['generation']):
                    raise BridgeError('Operator operation ID belongs to another decision', 409)
                result = dict(seen)
                result.update(changed=False, dry_run=dry_run,
                              effective=route in self.project(self.strip(policy)).routes)
                return result
            self.capacity(self.project(self.strip(policy)), route)
            if self.store.db.execute('SELECT COUNT(*) FROM return_route_decisions').fetchone()[0] >= MAX_DECISIONS:
                raise BridgeError('Return-route audit capacity reached; preserve decisions', 507)
            result = dict(operation_id=operation_id, action=action, conversation=conversation,
                          sender=sender, recipient=recipient, **scope, created=time.time())
            if not dry_run:
                self.store.db.execute('''INSERT INTO return_route_decisions
                    (operation_id,action,conversation,sender,recipient,owner,peer,native_id,generation,expires,created)
                    VALUES(:operation_id,:action,:conversation,:sender,:recipient,:owner,:peer,:native_id,:generation,:expires,:created)''', result)
            result.update(changed=not dry_run, dry_run=dry_run,
                          effective=route in self.project(self.strip(policy)).routes)
            return result

    def project(self, policy):
        base = self.strip(policy)
        if not base.multi_owner:
            return base  # Schema 1/2 retain their original authentication model.
        policy = copy.copy(base)
        policy.routes = set(base.routes)
        policy.agents = dict(base.agents)
        policy.conversations = dict(base.conversations)
        policy.return_route_base = base
        policy.return_route_additions = {}
        policy.return_route_guard = self
        with self.store.lock:
            rows = self.store.db.execute('''SELECT d.*,w.created AS withdrawn_at FROM return_route_decisions d
                JOIN (SELECT MAX(seq) seq FROM return_route_decisions
                      GROUP BY conversation,sender,recipient) latest ON d.seq=latest.seq
                LEFT JOIN return_route_withdrawals w ON w.grant_seq=d.seq
                ORDER BY d.seq''').fetchall()
            for raw in rows:
                decision = dict(raw)
                try:
                    route = self.usable(base, decision)
                    self.capacity(policy, route)
                except BridgeError:
                    continue
                if route in base.routes:
                    continue  # Existing static grants retain their own explicit lifecycle.
                cid, sender, recipient = route
                policy.routes.add(route)
                policy.return_route_additions[route] = decision['seq']
                entry = policy.conversations[cid]
                policy.conversations[cid] = dict(entry, routes=entry['routes']+[{'sender':sender,'recipient':recipient}])
                fingerprint, recipients = policy.agents[sender]
                # Every use checks the current decision. Keep existing identity
                # fingerprints/subscriptions, without introducing a wake opt-in.
                policy.agents[sender] = (fingerprint, recipients | {recipient})
        policy.routes = frozenset(policy.routes)
        return policy

    def assert_route(self, policy, route):
        with self.store.lock:
            decision = self.latest(route)
            if not decision or decision['seq'] != policy.return_route_additions.get(route):
                raise BridgeError('Explicit return-route decision changed', 403)
            self.usable(self.strip(policy), decision)


def add_parser(modes):
    parser = modes.add_parser('return-route', help='PRIVATE explicit reverse grant for an existing mailbox; never enrollment')
    parser.add_argument('--database-file', required=True)
    parser.add_argument('--policy-file', help='Required for grant; withdrawal uses only the stored exact decision')
    parser.add_argument('--accounts-file', help='Required for a leased grant; use the same configuration as the gateway')
    parser.add_argument('--action', choices=('grant','revoke'), required=True)
    for name in ('sender','recipient','conversation','operation-id'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--peer', choices=('mikkel@pop-os','work@pop-os'))
    parser.add_argument('--native-id')
    parser.add_argument('--expected-generation', type=int)
    parser.add_argument('--grant-operation-id', help='Required for revoke; the exact original grant decision ID')
    parser.add_argument('--dry-run', action='store_true')


def run(args):
    database = Path(args.database_file)
    if database.is_symlink() or not database.is_file():
        raise BridgeError('Return-route command requires the existing operator database')
    if database.stat().st_mode & 0o077:
        raise BridgeError('Operator database must be private')
    if (args.peer is None) != (args.native_id is None):
        raise BridgeError('Specify both owned peer and native ID, or neither')
    if args.action == 'grant' and not args.policy_file:
        raise BridgeError('Grant requires the current policy file')
    if args.dry_run:
        # Preview against a consistent SQLite snapshot. Even normal constructor
        # migrations, lease cleanup and clock bookkeeping stay off the live DB.
        import sqlite3
        from urllib.parse import quote
        source = sqlite3.connect('file:'+quote(str(database.resolve()))+'?mode=ro', uri=True)
        store = Store(':memory:')
        try:
            source.backup(store.db)
            store.return_routes = ReturnRoutes(store)
        except Exception:
            store.close()
            raise
        finally:
            source.close()
    else:
        store = Store(database)
    try:
        if args.action == 'grant' and args.accounts_file:
            from .session_leases import SessionLeases, load_accounts
            SessionLeases(store, load_accounts(args.accounts_file))
        policy = store.authorized_policy(Policy.load(args.policy_file)) if args.action == 'grant' else None
        return store.return_routes.decide(policy, action=args.action, operation_id=args.operation_id,
            sender=args.sender, recipient=args.recipient, conversation=args.conversation,
            peer=args.peer, native_id=args.native_id, expected_generation=args.expected_generation,
            dry_run=args.dry_run, grant_operation_id=args.grant_operation_id)
    finally:
        store.close()
