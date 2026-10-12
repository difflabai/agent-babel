#!/usr/bin/env python3
"""Private host-side enrollment; invoked as the app user by the operator wrapper."""
import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
from babel.core import Store
from babel.oauth import OAuthPolicy

POLICY_PATH = Path('/etc/agent-babel/agents.json')
DB_PATH = '/var/lib/agent-babel/bridge.sqlite3'

HUBS = {'ember': 'bits255.dots.ada_20261002', 'ada': 'bits255.grokbot.grok_20261002'}


def policies(request_file):
    request = json.loads(Path(request_file).read_text())
    assert set(request) == {'schema_version', 'participant', 'client', 'session', 'sha256'}
    assert request['schema_version'] == 1
    assert request['client'] in ('codex', 'cursor', 'claude', 'opencode', 'grokbot')
    assert re.fullmatch(r'[a-z][a-z0-9_-]{0,23}_[a-f0-9]{16}', request['session'])
    pid = 'bits255.' + request['client'] + '.' + request['session']
    assert request['participant'] == pid
    assert re.fullmatch(r'[a-f0-9]{64}', request['sha256']) and request['sha256'] != '0' * 64
    original = POLICY_PATH.read_bytes()
    oldcfg = json.loads(original)
    assert oldcfg['approval'] == 'automatic' and oldcfg['owners']['bits255']['enabled']
    newcfg = copy.deepcopy(oldcfg)
    existed = pid in oldcfg['participants']
    # This unlabelled schema1 endpoint is also used unattended. Once leases
    # are configured/durable, it may reconnect existing identities only.
    from babel.legacy_admission import assert_legacy_admission
    assert_legacy_admission(existed, DB_PATH)
    if existed:
        entry = oldcfg['participants'][pid]
        assert entry['state'] == 'active' and entry['accepted'] and entry['expires'] is None
        assert entry.get('sha256') == request['sha256']
        assert (entry['owner'], entry['client'], entry['session']) == ('bits255', request['client'], request['session'])
    else:
        import time
        newcfg['participants'][pid] = {'owner': 'bits255', 'client': request['client'], 'session': request['session'],
            'state': 'active', 'accepted': True, 'activated_at': int(time.time()) + 1, 'expires': None, 'sha256': request['sha256']}
    contacts = []
    for name, hub in HUBS.items():
        assert oldcfg['participants'][hub]['state'] == 'active'
        cid = 'report_' + request['client'] + '_' + request['session'].rsplit('_', 1)[1] + '_' + name
        expected = {'state': 'active', 'participants': [pid, hub], 'routes': [
            {'sender': pid, 'recipient': hub}, {'sender': hub, 'recipient': pid}]}
        if existed:
            assert oldcfg['conversations'].get(cid) == expected
        else:
            assert cid not in oldcfg['conversations']
            newcfg['conversations'][cid] = expected
        contacts.append({'recipient': hub, 'conversation_id': cid})
    old = OAuthPolicy(oldcfg)
    new = OAuthPolicy(newcfg)
    assert old.bindings == new.bindings
    if not existed:
        projection = copy.deepcopy(newcfg)
        projection['participants'].pop(pid)
        for contact in contacts:
            projection['conversations'].pop(contact['conversation_id'])
        assert projection == oldcfg
        assert old.routes < new.routes
        assert set(new.participants) == set(old.participants) | {pid}
    return original, oldcfg, newcfg, old, new, pid, contacts, existed


def apply(request_file):
    original, oldcfg, newcfg, old, new, pid, contacts, existed = policies(request_file)
    if existed:
        return {'participant': pid, 'changed': False, 'contacts': contacts}
    store = Store(DB_PATH)
    try:
        store.sync_policy(old)
        tables = [r[0] for r in store.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        def snapshot():
            return {t: [dict(r) for r in store.db.execute('SELECT * FROM ' + t + ' ORDER BY rowid')] for t in tables}
        before = snapshot()
        assert POLICY_PATH.read_bytes() == original
        # Operator-approved additive migration. Existing identity/principal entries
        # and grants are byte-equivalent. Retain exact verified callback metadata;
        # general runtime revocation and resubscription fencing stays unchanged.
        with store.transaction():
            for sub in before['subscriptions']:
                if sub['active']:
                    assert sub['role'] in old.participants
                    assert sub['auth_digest'] == old.agents[sub['role']][0]
                    new.assert_active(sub['role'])
                    store.db.execute('UPDATE subscriptions SET auth_digest=? WHERE id=?', (new.agents[sub['role']][0], sub['id']))
        store.sync_policy(new)
        after = snapshot()
        for table in tables:
            if table not in ('subscriptions', 'participant_bindings', 'credential_bindings'):
                assert before[table] == after[table], table
        expected = copy.deepcopy(before['subscriptions'])
        for sub in expected:
            if sub['active']:
                sub['auth_digest'] = new.agents[sub['role']][0]
        assert expected == after['subscriptions']
        assert [r for r in after['participant_bindings'] if r['id'] != pid] == before['participant_bindings']
        assert [r for r in after['credential_bindings'] if r['participant'] != pid] == before['credential_bindings']
        assert len(after['participant_bindings']) == len(before['participant_bindings']) + 1
        assert len(after['credential_bindings']) == len(before['credential_bindings']) + 1
        assert store.db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert POLICY_PATH.read_bytes() == original
        Path(request_file).with_name('policy.json').write_text(json.dumps(newcfg, indent=2) + '\n')
        return {'participant': pid, 'changed': True, 'contacts': contacts,
                'existing_message_rows_preserved': len(before['messages']), 'existing_data_and_callbacks': 'preserved'}
    finally:
        store.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', required=True)
    parser.add_argument('--validate', action='store_true')
    args = parser.parse_args()
    if args.validate:
        values = policies(args.request)
        print('existing' if values[-1] else 'new')
    else:
        print(json.dumps(apply(args.request)))
