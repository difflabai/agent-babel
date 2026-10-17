#!/usr/bin/env python3
"""Install an account PATH launcher once, without replacing Claude or its settings."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys

from install_account_client import atomic, checked


def install(target, claude, account_file, client_dir, *, apply=False):
    target, claude, account_file, client_dir = [Path(p).absolute() for p in
                                               (target, claude, account_file, client_dir)]
    checked(target)
    checked(target.parent, True)
    if not claude.is_file() or not os.access(claude, os.X_OK) or target.resolve() == claude.resolve():
        raise ValueError('Use the existing native Claude binary, distinct from the launcher')
    checked(account_file)
    if not account_file.is_file():
        raise ValueError('Existing approved account configuration required')
    entry = client_dir / 'claude_wake.py'
    checked(entry)
    if not entry.is_file():
        raise ValueError('Install the account client package first')
    receipt = target.parent / ('.' + target.name + '.babel-launcher.json')
    checked(receipt)
    previous = json.loads(receipt.read_text()) if receipt.exists() else None
    if previous is not None and (set(previous) != {'schema_version', 'sha256'} or previous['schema_version'] != 1):
        raise ValueError('Invalid launcher receipt')
    if target.exists() and (previous is None or hashlib.sha256(target.read_bytes()).hexdigest() != previous['sha256']):
        raise ValueError('Preserve existing launcher; choose a dedicated PATH directory')
    command = shlex.join([sys.executable, str(entry), 'launch', '--claude', str(claude),
                          '--account-file', str(account_file), '--'])
    raw = ('#!/bin/sh\n# Managed Babel Claude account launcher. Native permissions remain in force.\n'
           'exec ' + command + ' "$@"\n').encode()
    digest = hashlib.sha256(raw).hexdigest()
    if apply:
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        checked(target.parent, True)
        atomic(target, raw, 0o700)
        atomic(receipt, json.dumps({'schema_version': 1, 'sha256': digest}).encode(), 0o600)
    return {'state': 'installed' if apply else 'planned', 'target': str(target), 'sha256': digest,
            'activation': 'Prepend ' + str(target.parent) + ' to the account PATH once; native Claude preview consent still applies.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, type=Path)
    parser.add_argument('--claude', required=True, type=Path)
    parser.add_argument('--account-file', required=True, type=Path)
    parser.add_argument('--client-dir', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(install(args.target, args.claude, args.account_file, args.client_dir, apply=args.apply), indent=2))
    except (OSError, ValueError):
        parser.exit(2, 'Claude launcher installation failed; existing native binary/settings were preserved.\n')


if __name__ == '__main__':
    main()
