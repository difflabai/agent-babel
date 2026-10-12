"""Opt-in private enrollment for trusted UNIX accounts, not provider attestation.

No public enrollment RPC. Raw credentials never enter this module. The private
operator must derive peer from its pinned SSH collector, not from agent prose.
"""
import copy
import hashlib
import json
import re
import time
from pathlib import Path
from .core import BridgeError, fields
from .participants import digest

PEERS = frozenset(('mikkel@pop-os', 'work@pop-os'))
EMBER = 'bits255.dots.ada_20261002'
IDLE_SECONDS = 86400
CLIENTS = frozenset(('codex', 'claude', 'cursor', 'opencode', 'grokbot'))
AUTOMATIC_CLIENTS = frozenset(('codex','claude','cursor'))
NATIVE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_:-]{7,127}\Z')
SHA = re.compile(r'[a-f0-9]{64}\Z')


def load_accounts(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise BridgeError('Trusted-account file must be private and regular')
    info = path.stat()
    if info.st_mode & 0o077 or info.st_size > 8192:
        raise BridgeError('Trusted-account file must be private and bounded')
    try:
        return json.loads(path.read_text())
    except (ValueError, UnicodeError):
        raise BridgeError('Invalid trusted-account configuration') from None


def stop_owned(store, participant, reason):
    store.db.execute("UPDATE subscriptions SET active=0,secret='',old_secret=NULL WHERE role=?", (participant,))
    # An in-flight delivery is uncertain; do not silently replay after resume.
    store.db.execute("""UPDATE outbox SET status=CASE WHEN status='leased' THEN 'quarantined' ELSE 'parked' END,
        last_error=?,lease_token=NULL,lease_until=NULL
        WHERE subscription_id IN (SELECT id FROM subscriptions WHERE role=?)
        AND status IN ('pending','leased')""", (reason, participant))


class SessionLeases:
    def __init__(self, store, config, clock=time.time):
        fields(config, ('schema_version', 'accounts', 'max_active', 'max_records', 'excluded_participants'),
               ('schema_version', 'accounts', 'max_active', 'max_records'))
        if type(config['schema_version']) is not int or config['schema_version'] != 1:
            raise BridgeError('Unsupported trusted-account schema')
        if not isinstance(config['accounts'], dict) or not config['accounts']:
            raise BridgeError('Explicit trusted accounts required')
        if set(config['accounts']) - PEERS:
            raise BridgeError('Only explicitly approved Pop UNIX accounts are eligible')
        for account, entry in config['accounts'].items():
            fields(entry, ('enabled', 'clients'), ('enabled', 'clients'))
            if (type(entry['enabled']) is not bool or not isinstance(entry['clients'], list)
                    or not entry['clients'] or set(entry['clients']) - CLIENTS
                    or len(set(entry['clients'])) != len(entry['clients'])):
                raise BridgeError('Explicit account client allowlist required')
        for key, cap in (('max_active', 32), ('max_records', 4096)):
            if type(config[key]) is not int or not 1 <= config[key] <= cap:
                raise BridgeError('Trusted-session capacity must be explicitly bounded')
        if config['max_records'] < config['max_active']:
            raise BridgeError('History capacity cannot be below active capacity')
        excluded=config.get('excluded_participants',[])
        from .participants import PARTICIPANT
        if not isinstance(excluded,list) or len(excluded)>64 or any(not isinstance(pid,str) or not PARTICIPANT.fullmatch(pid) for pid in excluded):
            raise BridgeError('Infrastructure exclusions must be explicit bounded participant IDs')
        self.store, self.config, self.clock = store, copy.deepcopy(config), clock
        with store.transaction():
            store.db.execute('''CREATE TABLE IF NOT EXISTS trusted_session_realms (
                peer TEXT PRIMARY KEY, revoked INTEGER NOT NULL DEFAULT 0)''')
            store.db.execute('''CREATE TABLE IF NOT EXISTS trusted_sessions (
                participant TEXT PRIMARY KEY, conversation TEXT NOT NULL,
                peer TEXT NOT NULL, client TEXT NOT NULL, native_id TEXT NOT NULL,
                sha256 TEXT NOT NULL, generation INTEGER NOT NULL, state TEXT NOT NULL,
                activated REAL NOT NULL, last_activity REAL NOT NULL, deadline REAL NOT NULL,
                profile TEXT NOT NULL DEFAULT 'ember_outbound', UNIQUE(peer,client,native_id))''')
            if 'profile' not in {r[1] for r in store.db.execute('PRAGMA table_info(trusted_sessions)')}:
                store.db.execute("ALTER TABLE trusted_sessions ADD COLUMN profile TEXT NOT NULL DEFAULT 'ember_outbound'")
            store.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS trusted_dynamic_conversation ON trusted_sessions(conversation) WHERE profile='ember_outbound'")
            store.db.execute('''CREATE TABLE IF NOT EXISTS trusted_session_evidence (
                participant TEXT NOT NULL, event_id TEXT NOT NULL, kind TEXT NOT NULL,
                received REAL NOT NULL, sha256 TEXT, PRIMARY KEY(participant,event_id))''')
            if 'sha256' not in {r[1] for r in store.db.execute('PRAGMA table_info(trusted_session_evidence)')}:
                store.db.execute('ALTER TABLE trusted_session_evidence ADD COLUMN sha256 TEXT')
            store.db.execute('''CREATE TABLE IF NOT EXISTS trusted_session_clock (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), high_water REAL NOT NULL)''')
            previous={r['peer'] for r in store.db.execute('SELECT peer FROM trusted_session_realms')}
            for removed in previous-set(self.config['accounts']):
                store.db.execute('UPDATE trusted_session_realms SET revoked=1 WHERE peer=?',(removed,))
            for peer, entry in self.config['accounts'].items():
                store.db.execute('INSERT OR IGNORE INTO trusted_session_realms(peer) VALUES(?)', (peer,))
                if not entry['enabled']:
                    store.db.execute('UPDATE trusted_session_realms SET revoked=1 WHERE peer=?', (peer,))
            for row in store.db.execute("SELECT s.participant FROM trusted_sessions s JOIN trusted_session_realms r ON r.peer=s.peer WHERE r.revoked=1 AND s.state!='revoked'").fetchall():
                pid=row['participant']
                store.db.execute("UPDATE trusted_sessions SET state='revoked',generation=generation+1 WHERE participant=?",(pid,))
                store.db.execute('UPDATE credential_bindings SET retired=1 WHERE participant=?',(pid,))
                self._stop_owned(pid,'trust_revoked')
        store.sessions = self

    def _now(self):
        now = self.clock()
        if not isinstance(now, (int, float)) or not 0 < now < 1e12:
            raise BridgeError('Session clock unavailable', 503)
        anchor = self.store.db.execute('SELECT high_water FROM trusted_session_clock').fetchone()
        if anchor and now < anchor['high_water']:
            raise BridgeError('Session clock moved backwards; operator reconciliation required', 503)
        self.store.db.execute('''INSERT INTO trusted_session_clock VALUES(1,?)
            ON CONFLICT(singleton) DO UPDATE SET high_water=excluded.high_water''', (now,))
        return now

    def _account(self, peer, client):
        entry = self.config['accounts'].get(peer)
        realm = self.store.db.execute('SELECT revoked FROM trusted_session_realms WHERE peer=?', (peer,)).fetchone()
        if (not entry or not entry['enabled'] or not realm or realm['revoked']
                or client not in entry['clients']):
            raise BridgeError('Trusted account or client is unavailable', 403)

    def row(self, participant):
        with self.store.lock:
            row = self.store.db.execute('SELECT * FROM trusted_sessions WHERE participant=?', (participant,)).fetchone()
            return dict(row) if row else None

    def _expire(self, now):
        # Only owned wake resources: never touch another participant's subscription.
        expired = self.store.db.execute("SELECT participant FROM trusted_sessions WHERE state='active' AND deadline<=?", (now,)).fetchall()
        for row in expired:
            pid = row['participant']
            self.store.db.execute("UPDATE trusted_sessions SET state='idle_expired' WHERE participant=?", (pid,))
            self._stop_owned(pid, 'idle_expired')
        return len(expired)

    def _stop_owned(self, participant, reason):
        stop_owned(self.store,participant,reason)

    def cleanup(self):
        with self.store.transaction():
            return self._expire(self._now())

    def assert_active(self, participant, generation=None):
        with self.store.lock:
            row = self.row(participant)
            if not row:
                return
            self._account(row['peer'], row['client'])
            anchor = self.store.db.execute('SELECT high_water FROM trusted_session_clock').fetchone()
            now = self.clock()
            if anchor and now < anchor['high_water']:
                raise BridgeError('Session clock moved backwards', 503)
            if row['state'] != 'active' or now >= row['deadline']:
                raise BridgeError('Session idle lease expired or revoked', 403)
            if generation is not None and row['generation'] != generation:
                raise BridgeError('Session credential generation changed', 403)

    def _capacity(self, base, pid):
        active = self.store.db.execute("SELECT participant FROM trusted_sessions WHERE state='active'").fetchall()
        count = sum(r['participant'] != pid for r in active)
        if count >= self.config['max_active']:
            raise BridgeError('Trusted active-session capacity reached', 429)
        # Explicit policy stays at its existing64-record limits. The additive
        # overlay is independently bounded to32 leases (<=96 roles/conversations
        # in RAM); durable inactive automatic records are never projected.
        dynamic=self.store.db.execute("SELECT COUNT(*) FROM trusted_sessions WHERE state='active' AND profile='ember_outbound' AND participant!=?",(pid,)).fetchone()[0]
        slot=int(pid not in base.participants)
        if len(base.participants)-len(getattr(base,'session_dynamic_roles',()))+dynamic+slot>96 or len(base.conversations)-len(getattr(base,'session_conversations',()))+dynamic+slot>96:
            raise BridgeError('Authorization projection capacity reached',429)

    @staticmethod
    def _request(client, native_id, sha256, event_id, kind):
        if (client not in CLIENTS or not isinstance(native_id, str) or not NATIVE.fullmatch(native_id)
                or not isinstance(sha256, str) or not SHA.fullmatch(sha256) or sha256 == '0'*64
                or not isinstance(event_id, str) or not NATIVE.fullmatch(event_id)
                or kind not in ('bootstrap', 'turn', 'resume')):
            raise BridgeError('Invalid account-local lifecycle request')

    def bootstrap(self, base, *, peer, client, native_id, sha256, event_id, kind='bootstrap', existing_participant=None, observed_at=None):
        """PRIVATE operator API. Peer must come from pinned account transport.

        Account-local IDs/events are trusted UNIX account assertions, not signed
        provider attestation. A collector scan uses bootstrap, never resume/turn.
        """
        self._request(client, native_id, sha256, event_id, kind)
        if not base.multi_owner or 'bits255' not in base.owners:
            raise BridgeError('Trusted sessions require the existing bits255 owner')
        base.assert_active(EMBER)
        if not base.owners['bits255']['enabled']:
            raise BridgeError('Owner disabled', 403)
        key = hashlib.sha256(json.dumps([peer, client, native_id], separators=(',', ':')).encode()).hexdigest()[:32]
        pid, cid = 'bits255.'+client+'.auto_'+key, 'report_auto_'+key+'_ember'
        with self.store.transaction():
            now = self._now(); self._account(peer, client); self._expire(now)
            # Only the PRIVATE pinned account operator can carry native observation
            # time. Public RPC/worker report timestamps remain unsupported. Queue
            # delays and retries must never turn old work into fresh activity.
            activity = now
            if observed_at is not None:
                import math
                if (type(observed_at) not in (int,float) or not math.isfinite(observed_at)
                        or observed_at <= 0 or observed_at > now or now-observed_at >= IDLE_SECONDS):
                    raise BridgeError('Native observation is stale or clock is inconsistent',409)
                activity = observed_at
            if existing_participant is not None:
                if not isinstance(existing_participant,str):raise BridgeError('Invalid existing participant reference')
                old=self.row(existing_participant)
                if not old or (old['peer'],old['client'],old['profile'])!=(peer,client,'existing_grants') or old['state']=='revoked':
                    raise BridgeError('Legacy instance is not bound to this trusted account/client',403)
                base.assert_active(existing_participant)
                if old['native_id']!=native_id:
                    if not old['native_id'].startswith('legacy:') or native_id.startswith('legacy:'):
                        raise BridgeError('Verified native binding cannot be reassigned',409)
                    conflict=self.store.db.execute('SELECT 1 FROM trusted_sessions WHERE peer=? AND client=? AND native_id=?',(peer,client,native_id)).fetchone()
                    if conflict:raise BridgeError('Native context already has another mailbox',409)
                    self.store.db.execute('UPDATE trusted_sessions SET native_id=? WHERE participant=?',(native_id,existing_participant))
            bound=self.store.db.execute('SELECT * FROM trusted_sessions WHERE peer=? AND client=? AND native_id=?',(peer,client,native_id)).fetchone()
            if bound:pid,cid=bound['participant'],bound['conversation']
            row = self.row(pid)
            adopted=bool(row and row['profile']=='existing_grants')
            if not row and client not in AUTOMATIC_CLIENTS:
                raise BridgeError('Automatic native adapter not implemented; existing account-proven migration only',403)
            if adopted:
                base.assert_active(pid)
            elif pid in base.participants or cid in base.conversations:
                raise BridgeError('Automatic identity conflicts with explicit policy', 409)
            tombstone = self.store.db.execute('SELECT state FROM participant_bindings WHERE id=?', (pid,)).fetchone()
            if tombstone and tombstone['state'] in ('closed', 'revoked'):
                raise BridgeError('Explicitly revoked identity cannot resume', 403)
            if row and row['state'] == 'revoked':
                raise BridgeError('Revoked session cannot resume', 403)
            seen = self.store.db.execute('SELECT sha256 FROM trusted_session_evidence WHERE participant=? AND event_id=?', (pid, event_id)).fetchone()
            if seen and kind=='resume' and seen['sha256']!=sha256:
                raise BridgeError('Resume event already belongs to a different credential generation',409)
            if row and row['state'] == 'idle_expired' and (kind != 'resume' or seen):
                raise BridgeError('Idle session needs fresh account-local resume evidence and credential rotation', 403)
            if any(value==sha256 and role!=pid for role,value in base.credential_digests.items()):
                raise BridgeError('Credential digest belongs to an explicitly configured participant',403)
            known = self.store.db.execute('SELECT * FROM credential_bindings WHERE digest=?', (sha256,)).fetchone()
            if known and (known['participant'] != pid or known['retired']):
                raise BridgeError('Credential digest is retired or belongs to another session', 403)
            if row and row['sha256'] != sha256 and kind != 'resume':
                raise BridgeError('Credential rotation requires explicit account-local resume', 409)
            if row and row['state'] == 'idle_expired' and row['sha256'] == sha256:
                raise BridgeError('Idle resume must rotate its credential', 403)
            if not row or row['state'] != 'active':
                self._capacity(base, pid)
            if not row:
                if self.store.db.execute('SELECT COUNT(*) FROM trusted_sessions').fetchone()[0] >= self.config['max_records']:
                    raise BridgeError('Trusted-session audit capacity reached; preserve history and review capacity', 507)
                self.store.db.execute('INSERT INTO trusted_sessions(participant,conversation,peer,client,native_id,sha256,generation,state,activated,last_activity,deadline) VALUES(?,?,?,?,?,?,1,\'active\',?,?,?)',
                                      (pid,cid,peer,client,native_id,sha256,now,activity,activity+IDLE_SECONDS))
                self.store.db.execute('INSERT INTO credential_bindings VALUES(?,?,0)', (sha256,pid))
            else:
                if row['sha256'] != sha256:
                    self.store.db.execute('UPDATE credential_bindings SET retired=1 WHERE digest=?', (row['sha256'],))
                    self.store.db.execute('INSERT INTO credential_bindings VALUES(?,?,0)', (sha256,pid))
                    self.store.db.execute('UPDATE trusted_sessions SET sha256=?,generation=generation+1 WHERE participant=?', (sha256,pid))
                    self._stop_owned(pid, 'credential_rotated')
                if not seen and kind in ('turn', 'resume'):
                    activity=max(activity,row['last_activity'])
                    self.store.db.execute("UPDATE trusted_sessions SET state='active',last_activity=?,deadline=? WHERE participant=?", (activity,activity+IDLE_SECONDS,pid))
            if not seen:
                if self.store.db.execute('SELECT COUNT(*) FROM trusted_session_evidence WHERE participant=?',(pid,)).fetchone()[0]>=8192:
                    raise BridgeError('Session evidence capacity reached; preserve dedup records',507)
                self.store.db.execute('INSERT INTO trusted_session_evidence(participant,event_id,kind,received,sha256) VALUES(?,?,?,?,?)', (pid,event_id,kind,now,sha256))
            if row and row['state']=='idle_expired':
                self._resume_reports(base,pid,cid,adopted,now)
            return {k:self.row(pid)[k] for k in ('participant','conversation','generation','state','deadline')}

    def _resume_reports(self, base, pid, cid, adopted, now):
        # Only unambiguous parked outbound reports to an unchanged live sister
        # subscription. Recipient-owned wakes remain disabled until resubscribe.
        rows=self.store.db.execute("""SELECT o.seq,m.source,m.recipient,m.conversation_id,s.auth_digest
            FROM outbox o JOIN messages m ON m.id=o.message_id JOIN subscriptions s ON s.id=o.subscription_id
            WHERE o.status='parked' AND o.last_error='idle_expired' AND m.status='queued'
            AND m.source=? AND s.role=m.recipient AND s.active=1 AND s.expires>?""",(pid,now)).fetchall()
        for row in rows:
            role=row['recipient']
            if role not in (EMBER,'bits255.grokbot.grok_20261002') or base.agents.get(role,(None,))[0]!=row['auth_digest']:continue
            try:
                if adopted:base.assert_route(row['conversation_id'],pid,role)
                elif role!=EMBER or row['conversation_id']!=cid:continue
                else:base.assert_active(EMBER)
            except BridgeError:continue
            self.store.db.execute("UPDATE outbox SET status='pending',last_error=NULL,lease_token=NULL,lease_until=NULL WHERE seq=? AND status='parked'",(row['seq'],))

    def adopt(self, base, *, peer, participant, native_id, evidence='server_reports'):
        """PRIVATE reviewed mapping to a pinned account, never inferred from name.

        Actual native ID when known; otherwise collector-proven account-local
        legacy:<digest> binding is supported and disclosed, not native attestation.
        Evidence absent: exactly24h bounded rollout grace from server admission.
        """
        if evidence not in ('server_reports','rollout_grace'):
            raise BridgeError('Select meaningful server reports or bounded rollout grace')
        if participant in (EMBER,'bits255.grokbot.grok_20261002') or participant in self.config.get('excluded_participants',[]):
            raise BridgeError('Explicit infrastructure identity is excluded from worker migration',403)
        entry=base.participants.get(participant)
        if not entry or entry['client'] not in CLIENTS or entry['owner']!='bits255':
            raise BridgeError('Only explicitly inventoried transient worker participants may migrate')
        if not isinstance(native_id,str) or not NATIVE.fullmatch(native_id):
            raise BridgeError('Explicit account-local binding required')
        base.assert_active(participant)
        if entry['expires'] is not None:
            raise BridgeError('Finite legacy invitations need explicit policy review before idle migration')
        routes=[r for r in base.routes if r[1]==participant]
        if not routes or not entry.get('sha256'):
            raise BridgeError('Migration requires existing reporting grants and its own static digest')
        with self.store.transaction():
            now=self._now();self._account(peer,entry['client']);self._expire(now)
            old=self.row(participant)
            if old:
                if (old['peer'],old['client'],old['native_id'],old['profile'])!=(peer,entry['client'],native_id,'existing_grants'):
                    raise BridgeError('Existing binding cannot be reassigned',409)
                return {k:old[k] for k in ('participant','conversation','state','deadline')}
            if self.store.db.execute('SELECT 1 FROM trusted_sessions WHERE peer=? AND client=? AND native_id=?',(peer,entry['client'],native_id)).fetchone():
                raise BridgeError('Native context already belongs to another identity',409)
            tombstone=self.store.db.execute('SELECT state FROM participant_bindings WHERE id=?',(participant,)).fetchone()
            if tombstone and tombstone['state'] in ('closed','revoked'):
                raise BridgeError('Permanent revocation cannot be migrated',403)
            self._capacity(base,participant)
            if self.store.db.execute('SELECT COUNT(*) FROM trusted_sessions').fetchone()[0]>=self.config['max_records']:
                raise BridgeError('Trusted-session audit capacity reached',507)
            activity=now;kind='rollout_grace'
            if evidence=='server_reports':
                for row in self.store.db.execute("SELECT created,text FROM messages WHERE source=? AND provenance='mcp' AND created<=? ORDER BY created DESC",(participant,now)):
                    value=row['text'].strip()
                    if len(value)>=16 and not re.fullmatch(r'(?:(?:ping|active|heartbeat|keep[ -]?alive)[\s!.:]*)+',value,re.I):
                        activity=row['created'];kind='historical_report';break
            self.store.db.execute("""INSERT INTO trusted_sessions
                (participant,conversation,peer,client,native_id,sha256,generation,state,activated,last_activity,deadline,profile)
                VALUES(?,?,?,?,?,?,1,'active',?,?,?,'existing_grants')""",
                (participant,sorted(routes)[0][0],peer,entry['client'],native_id,entry['sha256'],entry['activated_at'],activity,activity+IDLE_SECONDS))
            self.store.db.execute('INSERT OR IGNORE INTO credential_bindings VALUES(?,?,0)',(entry['sha256'],participant))
            self.store.db.execute('INSERT INTO trusted_session_evidence(participant,event_id,kind,received) VALUES(?,?,?,?)',(participant,'migration:'+participant,kind,now))
            self._expire(now)
            return {k:self.row(participant)[k] for k in ('participant','conversation','state','deadline')}

    def report_activity(self, participant, message_id, text):
        """Inside the message transaction, after ID dedup and route checks.

        Narrow fallback: new substantial bound outbound report, not proof of
        silent native coding activity. No ping or read operation renews access.
        """
        row = self.row(participant)
        if not row:
            return
        self.assert_active(participant)
        value = text.strip()
        if len(value) < 16 or re.fullmatch(r'(?:(?:ping|active|heartbeat|keep[ -]?alive)[\s!.:]*)+',value,re.I):
            return
        if self.store.db.execute('SELECT COUNT(*) FROM trusted_session_evidence WHERE participant=?',(participant,)).fetchone()[0]>=8192:
            raise BridgeError('Session evidence capacity reached; preserve dedup records',507)
        now = self._now()
        self.store.db.execute('UPDATE trusted_sessions SET last_activity=?,deadline=? WHERE participant=?',
                              (now, now+IDLE_SECONDS, participant))
        self.store.db.execute('INSERT OR IGNORE INTO trusted_session_evidence(participant,event_id,kind,received) VALUES(?,?,\'report\',?)',
                              (participant, 'message:'+message_id, now))

    def revoke(self, *, participant=None, peer=None):
        if (participant is None) == (peer is None):
            raise BridgeError('Select exactly one session or account to revoke')
        with self.store.transaction():
            if peer is not None:
                if peer not in PEERS:
                    raise BridgeError('Unknown trusted account')
                self.store.db.execute('UPDATE trusted_session_realms SET revoked=1 WHERE peer=?', (peer,))
                rows = self.store.db.execute('SELECT participant FROM trusted_sessions WHERE peer=?', (peer,)).fetchall()
            else:
                if not self.row(participant):
                    raise BridgeError('Unknown trusted session',404)
                rows = [{'participant': participant}]
            for row in rows:
                pid = row['participant']
                self.store.db.execute("UPDATE trusted_sessions SET state='revoked',generation=generation+1 WHERE participant=?", (pid,))
                self.store.db.execute('UPDATE credential_bindings SET retired=1 WHERE participant=?', (pid,))
                self._stop_owned(pid, 'trust_revoked')

    def project(self, base):
        """Fresh bounded authorization snapshot; no policy-file rewrites.

        Idle records remain durable outside the active projection and are not
        passed through permanent participant registry removal/revocation.
        """
        if not base.multi_owner:
            raise BridgeError('Trusted sessions require participant policy')
        clock_valid=True
        try:self.cleanup()
        except BridgeError as exc:
            if exc.status!=503:raise
            clock_valid=False  # Fail leased actors closed without blocking manual peers.
        policy = copy.copy(base)
        for attr in ('participants','conversations','agents','credential_digests'):
            setattr(policy, attr, dict(getattr(base, attr)))
        policy.routes = set(base.routes)
        if hasattr(base, 'static_digests'):
            policy.static_digests = dict(base.static_digests)
        # Strip only our previous projection, never explicit sibling grants.
        for pid in getattr(base, 'session_dynamic_roles', ()):
            policy.participants.pop(pid,None); policy.agents.pop(pid,None); policy.credential_digests.pop(pid,None)
            if hasattr(policy,'static_digests'): policy.static_digests.pop(pid,None)
        for cid in getattr(base,'session_conversations', ()):
            policy.conversations.pop(cid,None)
            policy.routes={r for r in policy.routes if r[0]!=cid}
        policy.session_generations={}; policy.session_dynamic_roles=set(); policy.session_conversations=set(); policy.session_leases=self
        policy.session_adopted_originals=dict(getattr(base,'session_adopted_originals',{}))
        with self.store.lock:
            rows=self.store.db.execute("SELECT * FROM trusted_sessions WHERE profile='existing_grants' OR state='active' ORDER BY participant").fetchall()
            for raw in rows:
                row=dict(raw); pid,cid=row['participant'],row['conversation']
                if row['profile']=='existing_grants':
                    # Keep explicit grants and data unchanged, but fence the actor
                    # with its current generation/lease even when idle/revoked.
                    if pid in policy.participants:
                        policy.participants[pid]=dict(policy.participants[pid],sha256=row['sha256'])
                        policy.credential_digests[pid]=row['sha256']
                        if hasattr(policy,'static_digests'):policy.static_digests[pid]=row['sha256']
                        original=policy.session_adopted_originals.setdefault(pid,(base.agents[pid],base.credential_digests.get(pid)))
                        old,original_digest=original
                        fingerprint=old[0] if row['generation']==1 and row['sha256']==original_digest else digest([old[0],row['generation'],row['sha256']])
                        policy.agents[pid]=(fingerprint,old[1])
                        policy.session_generations[pid]=row['generation']
                    continue
                if not clock_valid:continue
                try:self.assert_active(pid)
                except BridgeError:continue
                if not base.owners.get('bits255',{}).get('enabled'):
                    continue
                if pid in policy.participants or cid in policy.conversations:
                    raise BridgeError('Automatic identity conflicts with explicit policy',409)
                if len(policy.participants)>=96 or len(policy.conversations)>=96:
                    raise BridgeError('Authorization projection capacity reached',429)
                entry={'owner':'bits255','client':row['client'],'session':pid.split('.')[2],
                       'state':'active','accepted':True,'activated_at':int(row['activated']),
                       'expires':None,'sha256':row['sha256']}
                policy.participants[pid]=entry
                policy.conversations[cid]={'state':'active','participants':[pid,EMBER],
                    'routes':[{'sender':pid,'recipient':EMBER}],'approval':'automatic'}
                policy.routes.add((cid,pid,EMBER))
                policy.agents[pid]=(digest([pid,cid,row['sha256'],row['generation']]),frozenset((EMBER,)))
                policy.credential_digests[pid]=row['sha256']
                if hasattr(policy,'static_digests'):policy.static_digests[pid]=row['sha256']
                policy.session_generations[pid]=row['generation']; policy.session_dynamic_roles.add(pid); policy.session_conversations.add(cid)
        policy.routes=frozenset(policy.routes)
        return policy


class SuspendedGuard:
    """Removing activation config must never revive a migrated old bearer."""
    def __init__(self,store):self.store=store
    def assert_active(self,role,generation=None):
        if self.store.trusted_session_row(role):
            raise BridgeError('Trusted-session lifecycle configuration is disabled',403)


def suspended_policy(store,base):
    policy=copy.copy(base);policy.session_leases=SuspendedGuard(store);policy.session_generations={}
    with store.transaction():
        # Only owned resources; durable identities/claims/dedup remain resumable.
        rows=store.db.execute('SELECT participant FROM trusted_sessions').fetchall()
        for row in rows:
            pid=row['participant']
            store.db.execute("UPDATE subscriptions SET active=0,secret='',old_secret=NULL WHERE role=?",(pid,))
            store.db.execute("""UPDATE outbox SET status=CASE WHEN status='leased' THEN 'quarantined' ELSE 'parked' END,
                last_error='lifecycle_disabled',lease_token=NULL,lease_until=NULL
                WHERE subscription_id IN (SELECT id FROM subscriptions WHERE role=?) AND status IN ('pending','leased')""",(pid,))
    return policy


def rollback_policy(config,store):
    """Prepare, never write, a reviewed policy for downgrade after lease use.

    Disabling the flag in this release suspends leases safely. An older binary
    lacks that gate: revoke only migrated legacy actors in its private policy
    before downgrading. Grants/history stay intact; restore access explicitly.
    """
    result=copy.deepcopy(config)
    for row in store.db.execute("SELECT participant,sha256 FROM trusted_sessions WHERE profile='existing_grants'"):
        if row['participant'] in result['participants']:
            result['participants'][row['participant']]['state']='revoked'
            result['participants'][row['participant']]['sha256']=row['sha256']
    return result
