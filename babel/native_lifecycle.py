"""Account-local native lifecycle parser. No transcripts or provider calls.

Native hook context is an assertion by a trusted UNIX UID, not attestation.
Prompt text is inspected transiently to exclude maintenance; never persisted.
"""
import hashlib
import json
import re
from .account_bootstrap import UUID
from .prompt_intake import meaningful_prompt
from .core import BridgeError


def event_key(*parts):
    return 'native:' + hashlib.sha256(json.dumps(parts, separators=(',', ':')).encode()).hexdigest()


def parse(client, data, *, env=None):
    env = env or {}
    if env.get('CLAUDE_CODE_REMOTE') == 'true':
        raise BridgeError('Hosted automatic lifecycle is unsupported', 403)
    if client not in ('codex', 'claude') or not isinstance(data, dict):
        raise BridgeError('Native lifecycle adapter is unavailable')
    sid = data.get('session_id')
    if not isinstance(sid, str) or not UUID.fullmatch(sid):
        raise BridgeError('Native hook session ID is unavailable')
    sid = sid.lower()
    # Reject contradictory native environment; hooks do not depend on its presence.
    if client == 'codex' and env.get('CODEX_THREAD_ID',sid).lower() != sid:
        raise BridgeError('Native hook/environment session mismatch')
    if data.get('agent_id') or data.get('agent_type'):
        return None  # Subagent common context is the parent; never adopt it.
    name = data.get('hook_event_name')
    if name == 'SessionStart':
        source = data.get('source')
        if source == 'compact': return None
        if source not in ('startup','clear','resume','fork') or (client == 'codex' and source == 'fork'):
            raise BridgeError('Unsupported native start source')
        return {'client':client,'native_id':sid,'phase':'start','source':source}
    if name == 'UserPromptSubmit':
        turn = data.get('turn_id')
        if client == 'codex' and (not isinstance(turn,str) or not UUID.fullmatch(turn)):
            raise BridgeError('Native Codex turn ID is unavailable')
        if turn is not None and (not isinstance(turn,str) or not UUID.fullmatch(turn)):
            raise BridgeError('Invalid native turn ID')
        return {'client':client,'native_id':sid,'phase':'prompt','turn_id':turn,
                'meaningful':meaningful_prompt(data.get('prompt'))}
    if client == 'codex' and name == 'PostToolUse' and data.get('tool_name') in ('apply_patch','Edit','Write'):
        turn=data.get('turn_id');tool_id=data.get('tool_use_id')
        if not isinstance(turn,str) or not UUID.fullmatch(turn) or not isinstance(tool_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,128}',tool_id):
            raise BridgeError('Native work evidence IDs unavailable')
        return {'client':client,'native_id':sid,'phase':'work','turn_id':turn.lower(),'tool_use_id':tool_id}
    if (client == 'codex' and name == 'Stop') or (client == 'claude' and name == 'MessageDisplay'):
        if client == 'codex' and data.get('stop_hook_active'): return None
        if client == 'claude' and data.get('final') is not True: return None
        turn = data.get('turn_id')
        if not isinstance(turn,str) or not UUID.fullmatch(turn):
            raise BridgeError('Native completion turn ID is unavailable')
        return {'client':client,'native_id':sid,'phase':'finish','turn_id':turn.lower()}
    return None  # Compact, tools, notifications, end and timers cannot renew.
