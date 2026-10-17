#!/usr/bin/env python3
"""Opt-in account hook dispatcher, disabled until explicitly installed/trusted.

Only local metadata/digests are stored. No HTTP, model, enrollment transport,
native launch, heartbeat or periodic activity is performed by a hook.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
from account_session_helper import Helper, private, save, bind_reviewed
from babel.account_bootstrap import local_key
from babel.native_lifecycle import parse, event_key
from babel.core import BridgeError
from babel import prompt_intake

MAX_EVENTS = 8192


def invocation_context():
    # Stable for duplicate hooks within this native runtime, fresh after a
    # genuine process restart. Same-process repeated resumes conservatively
    # deduplicate; an ambiguous callback must not rotate repeatedly.
    pid = os.getppid()
    # A command hook may add one short-lived shell parent. Inspect only our
    # bounded ancestor metadata, never a process scan or native transcript.
    for _ in range(3):
        raw=(Path('/proc')/str(pid)/'stat').read_text()
        comm=raw.split('(',1)[1].rsplit(')',1)[0]
        fields=raw.rsplit(')',1)[1].split()
        start=fields[19]
        if comm not in ('sh','bash','zsh','dash'):break
        parent=int(fields[1])
        if parent<=1:raise BridgeError('Stable native runtime context unavailable')
        pid=parent
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    return f'{boot}:{pid}:{start}'


class Dispatcher:
    def __init__(self, helper, *, clock=time.time, invocation=invocation_context):
        self.helper, self.clock, self.invocation = helper, clock, invocation

    def flush(self, db, path, ctx):
        spool=self.helper.root/(ctx['client']+'-auto_'+local_key(self.helper.peer,ctx))
        if not spool.exists():spool.mkdir(mode=0o700)
        private(spool,True)
        folder = spool/'lifecycle-events'
        if not folder.exists(): folder.mkdir(mode=0o700)
        private(folder,True)
        for eid, raw in db.execute('SELECT id,request FROM events WHERE spooled=0').fetchall():
            target = folder/(event_key(eid)[7:]+'.json')
            if target.exists():
                private(target)
                if json.loads(target.read_text()) != json.loads(raw):
                    raise BridgeError('Lifecycle retry evidence changed')
            else: save(target,raw+'\n')
            directory_fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
            db.execute('UPDATE events SET spooled=1 WHERE id=?',(eid,))
            db.commit()

    def consume_prompts(self, db, ctx, cutoff):
        current_boot = prompt_intake.boot_id()
        old_boot = db.execute("SELECT value FROM state WHERE key='claude_prompt_boot'").fetchone()
        boot_changed = not old_boot or old_boot[0] != current_boot
        if boot_changed:
            # Prompt intake is atomic/process-durable without a synchronous
            # disk barrier. A new OS boot cannot borrow unfinished eligibility
            # whose newest invalidation might have been lost in that crash.
            db.execute('DELETE FROM turns WHERE finished=0')
            db.execute("DELETE FROM state WHERE key IN ('claude_prompt_floor','claude_pending_order')")
            db.execute("INSERT OR REPLACE INTO state VALUES('claude_prompt_boot',?)", (current_boot,))
        floor_row = db.execute("SELECT value FROM state WHERE key='claude_prompt_floor'").fetchone()
        floor = tuple(json.loads(floor_row[0])) if floor_row else (0, 0)
        folder, records, failed, garbage = prompt_intake.pending(self.helper.root, self.helper.peer, ctx['native_id'], cutoff, floor, current_boot, boot_changed)
        for _, item in records:
            turn = item['turn_id']
            if failed:
                continue  # Capacity loss must not borrow an earlier real prompt.
            if turn is not None:
                if not db.execute('SELECT 1 FROM turns WHERE id=?', (turn,)).fetchone() and db.execute('SELECT COUNT(*) FROM turns').fetchone()[0] >= MAX_EVENTS:
                    raise BridgeError('Native turn evidence capacity reached; retain history')
                db.execute('INSERT OR IGNORE INTO turns VALUES(?,?,0)', (turn, int(item['meaningful'])))
            elif tuple(item['order']) > floor:
                old = db.execute("SELECT value FROM state WHERE key='claude_pending_order'").fetchone()
                if not old or tuple(item['order']) > tuple(json.loads(old[0])):
                    db.execute("INSERT OR REPLACE INTO turns VALUES('claude-pending',?,0)", (int(item['meaningful']),))
                    db.execute("INSERT OR REPLACE INTO state VALUES('claude_pending_order',?)", (json.dumps(item['order']),))
        if failed:
            # Corrupt intake may have been a notification invalidating any
            # unfinished prompt, including explicit IDs already committed by a
            # prior consume/retry. Finished IDs and durable events stay intact.
            db.execute('UPDATE turns SET meaningful=0 WHERE finished=0')
            db.execute("INSERT OR REPLACE INTO turns VALUES('claude-pending',0,0)")
        db.commit()  # Commit eligibility before deleting retryable local intake.
        for name, _ in records:
            prompt_intake.remove(folder, name)
        for name in failed + garbage:
            prompt_intake.remove(folder, name)

    def reporting_hint(self, db, item):
        # One bounded advisory for an existing native worker's next real prompt.
        # This metadata is not proof that the model adopted the policy.
        if item['phase'] != 'prompt' or not item['meaningful']:
            return False
        previous = db.execute("SELECT value FROM state WHERE key='reporting_policy'").fetchone()
        if previous and previous[0] == 'compact-reports-v1':
            return False
        db.execute("INSERT OR REPLACE INTO state VALUES('reporting_policy','compact-reports-v1')")
        return True

    def dispatch(self, client, data, *, env=None):
        item = parse(client, data, env=env)
        if item is None: return {'status':'ignored'}
        observed_order = prompt_intake.observation(self.clock) if client == 'claude' else None
        if client == 'claude' and item['phase'] == 'prompt':
            return prompt_intake.record(self.helper.root, self.helper.peer, item, observed_order)
        ctx = {'client':client,'native_id':item['native_id'],'kind':'bootstrap',
               'event_id':'bootstrap:'+item['native_id']}
        # Optional reviewed mapping is shared with helper tool calls. No mapping
        # means a distinct new context; no other account/instance is auto-adopted.
        bind_reviewed(self.helper,self.helper.root.parent,ctx)
        path = self.helper.path(ctx)
        fd = os.open(path/'lifecycle.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            dbpath = path/'lifecycle.sqlite3'
            if dbpath.exists() or dbpath.is_symlink(): private(dbpath)
            else: save(dbpath,'')
            db = sqlite3.connect(dbpath)
            try:
                db.execute('CREATE TABLE IF NOT EXISTS turns(id TEXT PRIMARY KEY, meaningful INTEGER NOT NULL, finished INTEGER NOT NULL DEFAULT 0)')
                db.execute('CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
                db.execute('CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,request TEXT NOT NULL,spooled INTEGER NOT NULL DEFAULT 0)')
                if client == 'claude' and item['phase'] == 'finish':
                    self.consume_prompts(db, ctx, observed_order)
                self.flush(db,path,ctx)
                now = self.clock()
                row = db.execute("SELECT value FROM state WHERE key='high_water'").fetchone()
                if row and now < float(row[0]): raise BridgeError('Local lifecycle clock moved backwards')
                db.execute("INSERT OR REPLACE INTO state VALUES('high_water',?)",(str(now),))
                # Persist turn eligibility before accepting any completion. A
                # mailbox notification cannot borrow a prior real task's turn.
                reporting_hint = False
                if item['phase'] == 'prompt':
                    turn = item.get('turn_id') or 'claude-pending'
                    if not db.execute('SELECT 1 FROM turns WHERE id=?',(turn,)).fetchone() and db.execute('SELECT COUNT(*) FROM turns').fetchone()[0]>=MAX_EVENTS:
                        raise BridgeError('Native turn evidence capacity reached; retain history')
                    if turn == 'claude-pending':
                        db.execute('INSERT OR REPLACE INTO turns VALUES(?,?,0)',(turn,int(item['meaningful'])))
                    else:
                        db.execute('INSERT OR IGNORE INTO turns VALUES(?,?,0)',(turn,int(item['meaningful'])))
                    reporting_hint = self.reporting_hint(db, item)
                    if client in ('claude', 'grokbot') or not item['meaningful']:
                        db.commit(); return {'status':'tracked','activity_queued':False,'reporting_hint':reporting_hint}
                    kind, eid = 'turn',event_key(client,item['native_id'],turn,'prompt')
                elif item['phase'] == 'work':
                    turn=item['turn_id']
                    row=db.execute('SELECT meaningful,finished FROM turns WHERE id=?',(turn,)).fetchone()
                    if not row or not row[0] or row[1]:
                        db.commit();return {'status':'ignored','activity_queued':False}
                    kind,eid='turn',event_key(client,item['native_id'],turn,item['tool_use_id'],'work')
                elif item['phase'] == 'finish':
                    turn = item['turn_id']
                    row = db.execute('SELECT meaningful,finished FROM turns WHERE id=?',(turn,)).fetchone()
                    if not row and client == 'claude':
                        pending = db.execute("SELECT meaningful,finished FROM turns WHERE id='claude-pending'").fetchone()
                        pending_order = db.execute("SELECT value FROM state WHERE key='claude_pending_order'").fetchone()
                        if pending and (not pending_order or tuple(json.loads(pending_order[0])) <= tuple(observed_order)):
                            db.execute('INSERT INTO turns VALUES(?,?,0)',(turn,pending[0]))
                            db.execute("DELETE FROM turns WHERE id='claude-pending'")
                            row = (pending[0],0)
                    if client == 'claude':
                        previous_floor = db.execute("SELECT value FROM state WHERE key='claude_prompt_floor'").fetchone()
                        floor = max(tuple(json.loads(previous_floor[0])) if previous_floor else (0, 0), tuple(observed_order))
                        db.execute("INSERT OR REPLACE INTO state VALUES('claude_prompt_floor',?)", (json.dumps(floor),))
                    if not row or not row[0] or row[1]:
                        db.commit(); return {'status':'ignored','activity_queued':False}
                    db.execute('UPDATE turns SET finished=1 WHERE id=?',(turn,))
                    kind,eid = 'turn',event_key(client,item['native_id'],turn,'finish')
                else:
                    kind = 'resume' if item['source'] == 'resume' else 'bootstrap'
                    eid = event_key(client,item['native_id'],item['source'],self.invocation()) if kind=='resume' else ctx['event_id']
                last = db.execute("SELECT value FROM state WHERE key='last_work'").fetchone()
                if kind == 'turn' and last and now-float(last[0]) >= 86400:
                    # A genuine new task turn after local inactivity is resume
                    # evidence; a collector/poll cannot enter this branch.
                    kind = 'resume'
                previous = db.execute('SELECT request FROM events WHERE id=?',(eid,)).fetchone()
                if previous:
                    request = json.loads(previous[0])
                else:
                    if kind in ('turn','resume'):
                        db.execute("INSERT OR REPLACE INTO state VALUES('last_work',?)",(str(now),))
                    elif last is None:
                        db.execute("INSERT INTO state VALUES('last_work',?)",(str(now),))
                    if db.execute('SELECT COUNT(*) FROM events').fetchone()[0] >= MAX_EVENTS:
                        raise BridgeError('Lifecycle evidence capacity reached; retain history')
                    # Prepare before adding other files on first bootstrap.
                    token = path/'token'
                    if not token.exists():
                        if kind != 'bootstrap': raise BridgeError('Native session needs bootstrap first')
                        save(token,self.helper.token_factory()+'\n')
                    _,_,request = self.helper.prepare(ctx,eid if kind=='resume' else None)
                    candidate=path/'resume-token'
                    if kind=='turn' and candidate.exists():
                        private(candidate)
                        import hashlib
                        request['sha256']=hashlib.sha256(candidate.read_text().strip().encode()).hexdigest()
                    request.update(kind=kind,event_id=eid,observed_at=now)
                    db.execute('INSERT INTO events(id,request) VALUES(?,?)',(eid,json.dumps(request,sort_keys=True)))
                db.commit()
                self.flush(db,path,ctx)
                return {'status':'queued','activity_queued':kind in ('turn','resume'),'event_id':eid,'reporting_hint':reporting_hint}
            finally: db.close()
        finally: os.close(fd)


def main(raw=None):
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--client',choices=('codex','claude','grokbot'),required=True)
    p.add_argument('--account-file',required=True)
    a=p.parse_args()
    try:
        file=Path(a.account_file); private(file)
        if file.stat().st_size>4096: raise BridgeError('Account configuration too large')
        config=json.loads(file.read_text())
        if set(config)!={'schema_version','peer'} or config['schema_version']!=1:
            raise BridgeError('Invalid account configuration')
        raw=sys.stdin.buffer.read(65537) if raw is None else raw
        if len(raw)>65536: raise BridgeError('Native hook input too large')
        h=Helper(file.parent/'automatic-instances',config['peer'])
        data=json.loads(raw)
        result=Dispatcher(h).dispatch(a.client,data,env=os.environ)
        if a.client == 'grokbot':
            # Grok ignores SessionStart/UserPromptSubmit additionalContext and
            # consumes Stop decisions as control flow. Never emit a Claude
            # continuation response or claim wake is connected.
            if result.get('status') in ('queued', 'tracked'):
                try:
                    from babel.grok_account_wake import ensure_receiver
                    ensure_receiver(file)
                except (BridgeError, OSError, ValueError, RuntimeError):
                    print('Babel Grok wake unavailable; patched native notification control is required.', file=sys.stderr)
            print('{}')
            return
        if a.client == 'codex' and result.get('status') in ('queued', 'tracked'):
            if data.get('hook_event_name') == 'SessionStart' or result.get('activity_queued'):
                # The existing trusted lifecycle owns automatic wake startup.
                # No session registration command, new account or service unit.
                try:
                    from babel.account_wake import ensure_receiver
                    ensure_receiver(file)
                except (BridgeError, OSError, ValueError, RuntimeError):
                    print('Babel automatic receiver unavailable; existing task continues.', file=sys.stderr)
        # Advisory hooks do not block, inject prompts, continue or wake sessions.
        if data.get('hook_event_name')=='SessionStart' and result.get('status')=='queued':
            import shlex
            sid=data['session_id'].lower()
            command=' '.join(shlex.quote(v) for v in [sys.executable,str(Path(__file__).resolve().parent.parent/'account_session_helper.py'),
                'tool','--client',a.client,'--account-file',str(file),'--native-session',sid,'--tool','list_contacts'])
            text=('Babel prepared this session\'s private enrollment request; connected status is not yet verified. '
                  'Use the account helper with this exact native session, keeping JSON arguments on stdin: '+command+
                  '. Do not launch a replacement agent, share credentials, or treat queue acceptance as wake verification. '
                  'Follow the installed WORKER-INSTRUCTIONS.md and authenticated Ember/Ada coordinator rule.')
            print(json.dumps({'hookSpecificOutput':{'hookEventName':'SessionStart','additionalContext':text}}))
        elif data.get('hook_event_name')=='UserPromptSubmit' and result.get('reporting_hint'):
            text=("Babel compact reporting policy: use the local helper tool stage_report for worker notifications, "
                  "not the remote MCP tool. Notify substantive completion, failures, actionable blockers, "
                  "approval requests, questions and experiment transitions; routine progress/tool/subagent/status "
                  "reports stay local. Use stable task_ref/event_ref; questions use pending/resolved plus revision. "
                  "Approvals still require actual owner approval and never expand grants. Read the installed "
                  "WORKER-INSTRUCTIONS.md for the exact local helper contract and private detail reads.")
            print(json.dumps({'hookSpecificOutput':{'hookEventName':'UserPromptSubmit','additionalContext':text}}))
        else:print('{}')
    except (BridgeError,OSError,ValueError,KeyError,sqlite3.Error):
        print('{}')
        print('Babel lifecycle hook unavailable; existing task continues, pending evidence retained.',file=sys.stderr)


if __name__=='__main__': main()
