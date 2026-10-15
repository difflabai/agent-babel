"""Small, local-only Claude prompt journal. Never imports credentials or HTTP.

A prompt records eligibility, not lifecycle activity. The normal completion
handler consumes this metadata under its existing lifecycle lock. Prompt text
never reaches disk. No processes, network calls or background services are used.
"""
import hashlib
import json
import os
import pwd
import re
import stat
import time

UUID = re.compile(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}\Z')
MAX_PENDING = 128
REPORTING_HINT = (
    'Babel compact reporting policy: use the local helper tool stage_report for worker notifications, '
    'not the remote MCP tool. Notify substantive completion, failures, actionable blockers, '
    'approval requests, questions and experiment transitions; routine progress/tool/subagent/status '
    'reports stay local. Use stable task_ref/event_ref; questions use pending/resolved plus revision. '
    'Approvals still require actual owner approval and never expand grants. Read the installed '
    'WORKER-INSTRUCTIONS.md for the exact local helper contract and private detail reads.'
)


def no_symlinks(path):
    path = os.path.abspath(os.fspath(path))
    current = path
    while True:
        try:
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise ValueError('Prompt intake refuses symlinked paths')
        except FileNotFoundError:
            pass
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return path


def private(path, directory=False):
    path = no_symlinks(path)
    info = os.stat(path)
    if (info.st_uid != os.getuid() or info.st_mode & 0o077 or
            not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise ValueError('Prompt intake needs owned private paths')
    return path


def meaningful_prompt(text):
    if not isinstance(text, str) or not text.strip():
        return False
    text = text.strip().lower()
    if text.startswith(('babel mailbox notification', 'babel channel notification')):
        return False
    words = re.findall(r'[a-z]+', text)
    return bool(words) and not all(w in {'ping','pong','heartbeat','keepalive','active','status','check','poll'} for w in words)


def parse_prompt(data, env=None):
    env = os.environ if env is None else env
    if env.get('CLAUDE_CODE_REMOTE') == 'true':
        raise ValueError('Hosted automatic lifecycle is unsupported')
    sid = data.get('session_id')
    if not isinstance(sid, str) or not UUID.fullmatch(sid):
        raise ValueError('Native Claude session ID unavailable')
    if data.get('agent_id') or data.get('agent_type'):
        return None
    turn = data.get('turn_id')
    if turn is not None and (not isinstance(turn, str) or not UUID.fullmatch(turn)):
        raise ValueError('Invalid native turn ID')
    return {'client': 'claude', 'native_id': sid.lower(), 'phase': 'prompt',
            'turn_id': turn.lower() if turn else None, 'meaningful': meaningful_prompt(data.get('prompt'))}


def boot_id():
    with open('/proc/sys/kernel/random/boot_id') as stream:
        value = stream.read(64).strip()
    if not UUID.fullmatch(value):
        raise ValueError('Native boot context unavailable')
    return value


def observation(clock=time.time):
    observed = clock()
    if type(observed) not in (int, float) or not 0 < observed < 1e12:
        raise ValueError('Prompt observation clock unavailable')
    return [int(observed * 1e9), time.monotonic_ns()]


def location(root, peer, sid, create=False):
    if peer not in ('mikkel@pop-os', 'work@pop-os') or pwd.getpwuid(os.getuid()).pw_name != peer.split('@')[0]:
        raise ValueError('Prompt account is not approved')
    root = no_symlinks(root)
    if create:
        os.makedirs(root, mode=0o700, exist_ok=True)
    private(root, True)
    key = hashlib.sha256(json.dumps([peer, 'claude', sid], separators=(',', ':')).encode()).hexdigest()[:32]
    spool = os.path.join(root, 'claude-auto_'+key)
    folder = os.path.join(spool, 'prompt-events')
    if create:
        for path in (spool, folder):
            try: os.mkdir(path, 0o700)
            except FileExistsError: pass
            private(path, True)
    return spool, folder


def publish(folder, record):
    # One tiny atomic, process-durable record; no shared lock, SQLite, history replay,
    # credential preparation, transport, or waiting for another hook.
    nonce = os.urandom(12).hex()
    stamp = str(record['order'][0]).zfill(21)+'-'+str(record['order'][1]).zfill(21)+'-b'+record['boot_id'].replace('-','')+'-'+nonce
    temporary = os.path.join(folder, '.pending-'+stamp)
    if record['turn_id'] is None:
        name = 'p-'+str(record['order'][0]).zfill(21)+'-'+str(record['order'][1]).zfill(21)+'-'+nonce+'.json'
    else:
        name = 't-'+record['turn_id']+'.json'
    target = os.path.join(folder, name)
    fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(record, separators=(',', ':'))+'\n')
        if record['turn_id'] is None:
            os.replace(temporary, target)
        else:
            try: os.link(temporary, target, follow_symlinks=False)
            except FileExistsError: private(target)
            os.unlink(temporary)
        # Do not synchronously flush the home filesystem on the prompt path.
        # Completion commits eligibility to SQLite; boot fencing invalidates
        # any uncommitted intake lost during an OS restart.
    except BaseException:
        # Keep an order-bound failure marker so a later completion cannot
        # borrow a prior meaningful prompt when this intake was interrupted.
        failed = os.path.join(folder, 'failed-'+stamp)
        try: os.replace(temporary, failed)
        except FileNotFoundError:
            fd = os.open(failed, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600);os.close(fd)
        raise
    if record['turn_id'] is None:
        # Claude normally has one pending prompt without a turn ID. Coalesce
        # only that pending slot, keeping the newest observation even when
        # older concurrent writers finish later. Explicit IDs retain dedup rows.
        with os.scandir(folder) as entries:
            names = [entry.name for entry in entries if entry.name.startswith('p-') and entry.name.endswith('.json')]
        latest = max(names, default=name)
        for old in names:
            if old != latest:
                remove(folder, old)


def record(root, peer, item, order):
    spool, folder = location(root, peer, item['native_id'], create=True)
    overflow = os.path.join(folder, 'overflow')
    if os.path.lexists(overflow):
        private(overflow)
        raise ValueError('Prompt backlog needs completion processing')
    existing = os.path.join(folder, 't-'+item['turn_id']+'.json') if item['turn_id'] else None
    if existing and os.path.lexists(existing):
        private(existing)  # An explicit-ID retry consumes no additional capacity.
    else:
        with os.scandir(folder) as entries:
            count = 0
            for _ in entries:
                count += 1
                if count >= MAX_PENDING:
                    try:
                        fd = os.open(overflow, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600);os.close(fd)
                    except FileExistsError: pass
                    raise ValueError('Prompt backlog capacity reached')
        publish(folder, {'schema_version': 2, 'boot_id': boot_id(), 'native_id': item['native_id'],
                        'turn_id': item['turn_id'], 'meaningful': item['meaningful'], 'order': order})
    hint = False
    if item['meaningful']:
        marker = os.path.join(spool, 'reporting-policy-v1')
        try:
            fd = os.open(marker, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600);os.close(fd);hint = True
        except FileExistsError:
            private(marker)
    return {'status': 'tracked', 'activity_queued': False, 'reporting_hint': hint}


def submit(account_file, data, env=None):
    account_file = private(account_file)
    if os.stat(account_file).st_size > 4096:
        raise ValueError('Account configuration too large')
    with open(account_file) as f:
        config = json.load(f)
    if set(config) != {'schema_version','peer'} or type(config['schema_version']) is not int or config['schema_version'] != 1:
        raise ValueError('Invalid account configuration')
    item = parse_prompt(data, env)
    if item is None:
        return {'status': 'ignored'}
    return record(os.path.join(os.path.dirname(account_file), 'automatic-instances'), config['peer'], item, observation())


def pending(root, peer, sid, cutoff, floor=(0,0), current_boot=None, boot_changed=False):
    current_boot = current_boot or boot_id()
    _, folder = location(root, peer, sid)
    if not os.path.exists(folder):
        return folder, [], [], []
    private(folder, True)
    result, failed, garbage = [], [], []
    with os.scandir(folder) as entries:
        for entry in entries:
            if entry.name.startswith(('.pending-', 'failed-')):
                try: private(entry.path)
                except FileNotFoundError: continue
                try: order = tuple(int(n) for n in entry.name.split('-')[1:3])
                except ValueError: raise ValueError('Invalid interrupted prompt marker') from None
                if len(order) != 2: raise ValueError('Invalid interrupted prompt marker')
                parts = entry.name.split('-')
                tag = parts[3] if len(parts)>3 and parts[3].startswith('b') else None
                if (tag and tag != 'b'+current_boot.replace('-','')) or (tag is None and boot_changed):
                    garbage.append(entry.name);continue
                if order <= tuple(floor): garbage.append(entry.name)
                elif order <= tuple(cutoff): failed.append(entry.name)
                continue
            if not entry.name.endswith('.json'):
                continue
            try:
                path = private(entry.path)
                if os.stat(path).st_size > 1024:
                    raise ValueError('Prompt intake record too large')
                with open(path) as f:
                    value = json.load(f)
            except FileNotFoundError:
                continue
            if isinstance(value,dict) and value.get('schema_version') == 1:
                garbage.append(entry.name);continue  # Pre-upgrade intake has no boot binding.
            if (not isinstance(value,dict) or set(value) != {'schema_version','boot_id','native_id','turn_id','meaningful','order'} or
                    type(value['schema_version']) is not int or value['schema_version'] != 2 or value['native_id'] != sid or type(value['meaningful']) is not bool or
                    not isinstance(value['order'], list) or len(value['order']) != 2 or
                    any(type(n) is not int or n <= 0 for n in value['order']) or
                    (value['turn_id'] is not None and (not isinstance(value['turn_id'],str) or not UUID.fullmatch(value['turn_id'])))):
                raise ValueError('Invalid prompt intake record')
            if value['boot_id'] != current_boot:
                garbage.append(entry.name);continue
            if tuple(value['order']) <= tuple(cutoff):
                result.append((entry.name, value))
    result.sort(key=lambda item: tuple(item[1]['order']))
    overflow = os.path.lexists(os.path.join(folder, 'overflow'))
    if overflow:
        private(os.path.join(folder, 'overflow'));failed.append('overflow')
    return folder, result, failed, garbage


def remove(folder, name):
    path = os.path.join(folder, name)
    try:
        private(path);os.unlink(path)
    except FileNotFoundError:
        pass
