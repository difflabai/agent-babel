"""Account-local native lifecycle parser. No transcripts or provider calls.

Native hook context is an assertion by a trusted UNIX UID, not attestation.
Prompt text is inspected transiently to exclude maintenance; never persisted.
"""
import hashlib
import json
import re
from .account_bootstrap import UUID, OPENCODE_SESSION, OPENCODE_MESSAGE
from .prompt_intake import meaningful_prompt
from .core import BridgeError


def event_key(*parts):
    return 'native:' + hashlib.sha256(json.dumps(parts, separators=(',', ':')).encode()).hexdigest()


def parse(client, data, *, env=None):
    env = env or {}
    if env.get('CLAUDE_CODE_REMOTE') == 'true':
        raise BridgeError('Hosted automatic lifecycle is unsupported', 403)
    if (client != 'grokbot' and isinstance(data, dict) and 'hookEventName' in data and
            'sessionId' in data and (env.get('GROK_SESSION_ID') or env.get('GROK_HOOK_EVENT'))):
        # Grok imports global Claude/Cursor hooks by default. A compatibility
        # callback is still Grok; never mint a different client's identity.
        return None
    if client == 'grokbot':
        from .grok_lifecycle import parse as grok_parse
        return grok_parse(data, env=env)
    if client == 'opencode':
        if not isinstance(data,dict): raise BridgeError('Invalid OpenCode event')
        sid=data.get('session_id')
        if not isinstance(sid,str) or not OPENCODE_SESSION.fullmatch(sid):
            raise BridgeError('OpenCode native session ID is unavailable')
        if data.get('parent_id'): return None
        name=data.get('hook_event_name')
        if name in ('session.created','session.observed'):
            return {'client':client,'native_id':sid,'phase':'start','source':'startup'}
        if name=='chat.message':
            turn=data.get('message_id')
            if not isinstance(turn,str) or not OPENCODE_MESSAGE.fullmatch(turn):
                raise BridgeError('OpenCode native message ID is unavailable')
            return {'client':client,'native_id':sid,'phase':'prompt','turn_id':turn,
                    'meaningful':meaningful_prompt(data.get('prompt'))}
        return None
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
