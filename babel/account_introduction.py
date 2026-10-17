"""One fixed authenticated introduction for an opted-in fresh native mailbox.

The standing worker onboarding rule authorizes this message. It enables the
existing coordinator reply capability; it does not assert model wake, receipt,
readiness or task completion, and never changes lifecycle evidence or grants.
"""
import fcntl
import hashlib
import math
import os
import time

from account_session_helper import private
from .account_bootstrap import local_key
from .account_enrollment import Configuration, atomic, canonical, read_json
from .core import BridgeError, identifier

EMBER = 'bits255.dots.ada_20261002'
TEXT = 'Babel hello.'  # <16 ASCII characters: existing report_activity ignores it.
LEDGER = 'connection-introduction.json'
STATES = frozenset(('pending', 'queued', 'acknowledged', 'draft', 'existing', 'awaiting_approval'))


def binding(box, contacts):
    config = Configuration(box.root / 'trusted-account.json')
    if not config.enabled:
        return None
    context = {'client': box.client, 'native_id': box.sid}
    key = local_key(config.peer, context)
    participant = 'bits255.' + box.client + '.auto_' + key
    conversation = 'report_auto_' + key + '_ember'
    if (box.root != config.root or box.helper.peer != config.peer
            or box.helper.root != config.instances
            or box.path != config.instances / (box.client + '-auto_' + key)
            or box.participant != participant):
        return None  # Reviewed legacy paths/participants retain their own onboarding.
    private(box.path, True)
    manifest = read_json(box.path / 'trusted-enrollment.json')
    if (manifest.get('client') != box.client or manifest.get('native_id') != box.sid
            or 'existing_participant' in manifest):
        return None
    if (not isinstance(contacts, list) or len(contacts) != 1 or not isinstance(contacts[0], dict)
            or contacts[0].get('recipient') != EMBER
            or contacts[0].get('conversation_id') != conversation):
        return None
    message_id = 'connection_' + hashlib.sha256(canonical([participant, conversation, 1]).encode()).hexdigest()
    return {'schema_version': 1, 'participant': participant, 'conversation_id': conversation,
            'message_id': message_id}


def valid_state(value, expected):
    if (not isinstance(value, dict) or set(value) != set(expected) | {'state', 'attempts', 'retry_at', 'proof_id'}
            or type(value['schema_version']) is not int
            or any(value[k] != v for k, v in expected.items())
            or value['state'] not in STATES or type(value['attempts']) is not int
            or not 0 <= value['attempts'] <= 2**31
            or type(value['retry_at']) not in (int, float) or not math.isfinite(value['retry_at'])
            or value['retry_at'] < 0):
        raise BridgeError('Retain mismatched introduction proof')
    identifier(value['proof_id'])
    if value['state'] not in ('existing', 'awaiting_approval') and value['proof_id'] != expected['message_id']:
        raise BridgeError('Retain mismatched introduction message')
    return value


def verified_message(row, expected, *, exact=False):
    if (not isinstance(row, dict) or row.get('source') != expected['participant']
            or row.get('recipient') != EMBER or row.get('conversation_id') != expected['conversation_id']
            or row.get('provenance') != 'mcp'
            or row.get('status') not in ('queued', 'acknowledged', 'draft')):
        raise BridgeError('Unverified introduction response')
    identifier(row.get('id'))
    if exact and (row['id'] != expected['message_id'] or row.get('text') != TEXT or row.get('reply_to') is not None):
        raise BridgeError('Introduction response changed')
    return row


def ensure_introduction(box, contacts, *, clock=time.time):
    """Best effort under the native poll. Failure never consumes an inbox item."""
    fd = None
    try:
        expected = binding(box, contacts)
        if expected is None:
            return 'disabled'
        lock = box.path / 'connection-introduction.lock'
        if lock.exists() or lock.is_symlink():
            private(lock)
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise BridgeError('Owned introduction lock required')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 'busy'
        path = box.path / LEDGER
        state = {**expected, 'state': 'pending', 'attempts': 0, 'retry_at': 0,
                 'proof_id': expected['message_id']}
        if path.exists() or path.is_symlink():
            state = valid_state(read_json(path), expected)
            if state['state'] != 'pending':
                return state['state']
        if state['retry_at'] > clock():
            return 'backoff'
        # Persist retry intent before either authenticated read or send. A lost
        # stage response replays the exact ID/body under server ID deduplication.
        state['attempts'] += 1
        state['retry_at'] = clock() + min(300, 20 * 2**min(state['attempts'] - 1, 4))
        atomic(path, canonical(state) + '\n')
        history = box.call('bridge_history', {'limit': 100}, timeout=5)
        if (not isinstance(history, dict) or not isinstance(history.get('messages'), list)
                or len(history['messages']) > 100):
            raise BridgeError('Invalid own bridge history')
        for row in history['messages']:
            if not isinstance(row, dict) or row.get('conversation_id') != expected['conversation_id']:
                raise BridgeError('Unexpected automatic conversation history')
            if row.get('source') == expected['participant'] and row.get('status') in ('queued', 'acknowledged', 'draft'):
                row = verified_message(row, expected)
                state.update(state='awaiting_approval' if row['status'] == 'draft' else 'existing',
                             proof_id=row['id'], retry_at=0)
                atomic(path, canonical(state) + '\n')
                return state['state']
        if len(history['messages']) == 100:
            # A prior outgoing introduction may be outside this bounded page.
            # Do not create another message from incomplete history evidence.
            raise BridgeError('Retain full automatic conversation history')
        # A canonical account opt-out during the history call stops the send.
        if binding(box, contacts) != expected:
            return 'disabled'
        args = {'recipient': EMBER, 'conversation_id': expected['conversation_id'],
                'message_id': expected['message_id'], 'text': TEXT}
        result = box.call('stage_message', args, timeout=5)
        if not isinstance(result, dict) or type(result.get('duplicate')) is not bool:
            raise BridgeError('Unverified introduction acceptance')
        row = verified_message(result.get('message'), expected, exact=True)
        state.update(state=row['status'], retry_at=0)
        atomic(path, canonical(state) + '\n')
        return state['state']
    except Exception:
        # Retain the private intent for exact retry; never leak remote errors,
        # treat a draft as approved, or block processing an existing inbox item.
        return 'retry'
    finally:
        if fd is not None:
            os.close(fd)
