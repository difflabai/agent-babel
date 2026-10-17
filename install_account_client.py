#!/usr/bin/env python3
"""Install only the account client code; never configure or invoke native hooks."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import uuid

SOURCE = Path(__file__).resolve().parent
RECEIPT = '.account-client-install.json'
# Libraries first, public entrypoint last. No server/auth/policy implementation.
CLIENT_FILES = (
    'babel/account_bootstrap.py', 'babel/reporting.py', 'babel/prompt_intake.py',
    'babel/native_lifecycle.py', 'babel/grok_lifecycle.py', 'account_session_helper.py',
    'babel/account_enrollment.py', 'account_enrollment.py',
    'babel/native_receiver.py', 'babel/account_wake.py', 'account_wake.py',
    'babel/grok_receiver.py', 'babel/grok_account_wake.py', 'grok_account_wake.py',
    'babel/lifecycle_dispatcher.py', 'account_lifecycle_hook.py',
    'babel/claude_wake.py', 'claude_wake.py',
    'babel/opencode_bridge.py', 'opencode_account_bridge.py',
)
# Existing bundles retain these files verbatim. Fresh client-only installations
# need their error/validation definitions; none of the Store code is invoked.
SUPPORT_FILES = ('babel/__init__.py', 'babel/core.py')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(path, directory=False):
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('Refusing symlinked package path')
    if path.exists():
        info = path.stat()
        valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not valid or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('Package paths must be owned and private')


def atomic(path, raw, mode):
    checked(path)
    fd, temporary = tempfile.mkstemp(prefix='.account-client-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_receipt(target):
    path = target / RECEIPT
    checked(path)
    if not path.exists():
        return None
    if path.stat().st_size > 16384:
        raise ValueError('Package receipt too large')
    value = json.loads(path.read_text())
    if (not isinstance(value, dict) or value.get('schema_version') != 1
            or not isinstance(value.get('files'), dict)
            or set(value['files']) - set(CLIENT_FILES + SUPPORT_FILES)):
        raise ValueError('Invalid package receipt')
    for name, sha in value['files'].items():
        path = target / name
        checked(path)
        if not path.is_file() or digest(path.read_bytes()) != sha:
            raise ValueError('Installed source changed; preserve and review: ' + name)
    return value


def plan(target, *, adopt_existing=False):
    target = Path(os.path.abspath(target))
    checked(target, True)
    if target.exists():
        checked(target / 'babel', True)
    previous = read_receipt(target)
    managed = previous['files'] if previous else {}
    names = [p for p in SUPPORT_FILES if p in managed or not (target / p).exists()]
    names += list(CLIENT_FILES)
    data = {}
    for name in names:
        source = SOURCE / name
        if source.is_symlink() or not source.is_file():
            raise ValueError('Incomplete account client source: ' + name)
        raw = source.read_bytes()
        compile(raw, name, 'exec')
        path = target / name
        checked(path)
        if path.exists() and name not in managed and path.read_bytes() != raw and not adopt_existing:
            raise ValueError('Unmanaged client source; review then use --adopt-existing: ' + name)
        data[name] = raw
    # These are intentional dependencies, even when the package does not own them.
    for name in SUPPORT_FILES:
        checked(target / name)
    hashes = {name: digest(raw) for name, raw in data.items()}
    before_hashes = {name: digest((target / name).read_bytes()) if (target / name).exists() else None
                     for name in list(data) + [RECEIPT]}
    return target, data, {
        'schema_version': 1, 'files': hashes,
        'bundle_sha256': digest(json.dumps(hashes, sort_keys=True).encode()),
        'adopt_existing': adopt_existing,
    }, before_hashes


def _install_unlocked(target, *, apply=False, adopt_existing=False):
    target, data, receipt, before_hashes = plan(target, adopt_existing=adopt_existing)
    if not apply:
        return {'state': 'planned', 'target': str(target), **receipt}
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    checked(target, True)
    (target / 'babel').mkdir(mode=0o700, exist_ok=True)
    checked(target / 'babel', True)
    backups = target / '.account-client-backups'
    checked(backups, True)
    backups.mkdir(mode=0o700, exist_ok=True)
    backup = backups / uuid.uuid4().hex
    backup.mkdir(mode=0o700)
    before, written = {}, []
    # Save only package code and its prior receipt. Never enumerate state,
    # account configuration, tokens, hooks, settings or unrelated source files.
    for name in list(data) + [RECEIPT]:
        path = target / name
        checked(path)
        if path.exists():
            raw, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            if digest(raw) != before_hashes[name]:
                raise ValueError('Source changed before snapshot: ' + name)
            saved = backup / name
            saved.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            atomic(saved, raw, mode)
            before[name] = {'sha256': digest(raw), 'mode': mode}
        else:
            if before_hashes[name] is not None:
                raise ValueError('Source removed before snapshot: ' + name)
            before[name] = None
    receipt['backup'] = str(backup)
    atomic(backup / 'before.json', json.dumps(before, sort_keys=True).encode(), 0o600)
    try:
        for name, raw in data.items():
            path = target / name
            old = before[name]
            # Refuse a source edit made after the initial review/snapshot.
            if (old is None and path.exists()) or (old and digest(path.read_bytes()) != old['sha256']):
                raise ValueError('Source changed during installation: ' + name)
            written.append(name)
            atomic(path, raw, old['mode'] if old else 0o600)
        current_receipt = digest((target / RECEIPT).read_bytes()) if (target / RECEIPT).exists() else None
        if current_receipt != before_hashes[RECEIPT]:
            raise ValueError('Receipt changed during installation')
        written.append(RECEIPT)
        atomic(target / RECEIPT, json.dumps(receipt, sort_keys=True).encode(),
               before[RECEIPT]['mode'] if before[RECEIPT] else 0o600)
        for name, sha in receipt['files'].items():
            if digest((target / name).read_bytes()) != sha:
                raise ValueError('Installed source verification failed: ' + name)
    except BaseException:
        conflicts = []
        for name in reversed(written):
            old = before[name]
            path = target / name
            try:
                checked(path)
            except ValueError:
                conflicts.append(name)
                continue
            current = digest(path.read_bytes()) if path.exists() else None
            if old and current == old['sha256']:
                continue  # A failed replace may have left the original intact.
            expected = digest(data[name]) if name != RECEIPT else digest(json.dumps(receipt, sort_keys=True).encode())
            if current not in {expected, None}:
                conflicts.append(name)
                continue  # Never erase an independent source edit during recovery.
            if old:
                atomic(path, (backup / name).read_bytes(), old['mode'])
            elif path.exists():
                path.unlink()
        if conflicts:
            raise ValueError('Rollback preserved independently changed source; inspect backup: ' + ', '.join(conflicts))
        raise
    return {'state': 'installed', 'target': str(target), **receipt}


def install(target, *, apply=False, adopt_existing=False):
    target = Path(os.path.abspath(target))
    if not apply:
        return _install_unlocked(target, adopt_existing=adopt_existing)
    checked(target, True)
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = target / '.account-client-install.lock'
    checked(lock)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _install_unlocked(target, apply=True, adopt_existing=adopt_existing)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, type=Path,
                        help='Owned private source directory; always explicit')
    parser.add_argument('--apply', action='store_true', help='Write the reviewed code-only plan')
    parser.add_argument('--adopt-existing', action='store_true',
                        help='Back up and replace reviewed unmanaged client files')
    args = parser.parse_args()
    try:
        print(json.dumps(install(args.target, apply=args.apply, adopt_existing=args.adopt_existing), indent=2))
    except (OSError, ValueError):
        parser.exit(2, 'Account client installation failed; preserve the package and backup for review.\n')


if __name__ == '__main__':
    main()
