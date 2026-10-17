"""Grok Build native hook context, never a Grok Bot/routine identity.

The installed CLI emits camelCase fields and additive Claude-compatible aliases.
Only bounded identity/activity metadata survives; prompt and tool content do not.
This adapter prepares requests, not enrollment authorization or native wake.
"""
import re

from .account_bootstrap import UUID
from .core import BridgeError
from .prompt_intake import meaningful_prompt

EVENTS = {'session_start': 'SessionStart', 'user_prompt_submit': 'UserPromptSubmit',
          'stop': 'Stop', 'session_end': 'SessionEnd'}
PROMPT_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_:-]{0,127}\Z')


def field(data, camel, snake):
    if camel in data and snake in data and data[camel] != data[snake]:
        raise BridgeError('Contradictory Grok native hook aliases')
    return data.get(camel, data.get(snake))


def session(data, *, env=None):
    if not isinstance(data, dict):
        raise BridgeError('Grok requires its native hook context')
    sid = field(data, 'sessionId', 'session_id')
    if not isinstance(sid, str) or not UUID.fullmatch(sid):
        raise BridgeError('Grok native session UUID is unavailable')
    sid = sid.lower()
    observed = (env or {}).get('GROK_SESSION_ID', sid)
    if not isinstance(observed, str) or observed.lower() != sid:
        raise BridgeError('Grok native hook/environment session mismatch')
    return sid


def event(data):
    camel, snake = data.get('hookEventName'), data.get('hook_event_name')
    if camel is not None:
        camel = EVENTS.get(camel, camel)
    if camel is not None and snake is not None and camel != snake:
        raise BridgeError('Contradictory Grok native hook events')
    return camel or snake


def parse(data, *, env=None):
    sid = session(data, env=env)
    if any(data.get(name) for name in ('agentId', 'agent_id', 'agentType', 'agent_type',
                                      'subagentType', 'subagent_type')):
        return None
    name = event(data)
    if not isinstance(name, str):
        raise BridgeError('Grok native hook event is unavailable')
    common = {'client': 'grokbot', 'native_id': sid}
    if name == 'SessionStart':
        source = data.get('source')
        # The native actor uses new/load; vendor-compatible versions may use
        # startup/resume. A reload/compact callback cannot rotate credentials.
        source = {'new': 'startup', 'load': 'resume'}.get(source, source)
        if source not in ('startup', 'resume'):
            return None
        return {**common, 'phase': 'start', 'source': source}
    if name not in ('UserPromptSubmit', 'Stop'):
        return None
    prompt_id = field(data, 'promptId', 'prompt_id')
    if not isinstance(prompt_id, str) or not PROMPT_ID.fullmatch(prompt_id):
        # Stop also fires for autonomous activity without a prompt ID. Never
        # borrow an earlier human prompt for an uncorrelated completion.
        return None
    if name == 'UserPromptSubmit':
        return {**common, 'phase': 'prompt', 'turn_id': prompt_id,
                'meaningful': meaningful_prompt(data.get('prompt'))}
    if field(data, 'stopHookActive', 'stop_hook_active') is not False or data.get('reason') != 'end_turn':
        return None
    return {**common, 'phase': 'finish', 'turn_id': prompt_id}
