#!/usr/bin/env python3
"""Install the account-wide OpenCode native plugin once. Dry run by default.

Does not alter opencode.json, launch OpenCode, enroll an identity, touch provider
credentials or change permission policies. Client code is installed separately
with install_account_client.py.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

SOURCE=Path(__file__).resolve().parent/'integrations/opencode/babel-wake.mjs'


def check(path, directory=False):
    for candidate in (path,*path.parents):
        if candidate.is_symlink(): raise ValueError('Refusing symlinked plugin path')
    if path.exists():
        info=path.stat()
        if info.st_uid!=os.getuid() or info.st_mode & 0o022 or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            raise ValueError('Plugin path must be owned and not writable by others')


def install(folder, *, apply=False):
    folder=Path(os.path.abspath(folder));check(folder,True)
    target=folder/'babel-wake.js';receipt=folder/'.babel-wake-install.json'
    check(target);check(receipt)
    raw=SOURCE.read_bytes();before=None
    if target.exists():
        before=target.read_bytes()
        if before!=raw:
            if not receipt.exists() or json.loads(receipt.read_text()).get('sha256')!=hashlib.sha256(before).hexdigest():
                raise ValueError('Plugin source changed; preserve and review')
    result={'state':'planned','plugin':str(target),'sha256':hashlib.sha256(raw).hexdigest()}
    if not apply:return result
    folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    # Recheck after planning. Do not overwrite an intervening edit.
    if (target.read_bytes() if target.exists() else None)!=before:raise ValueError('Plugin changed during planning')
    for path,body in ((target,raw),(receipt,(json.dumps({'schema_version':1,'sha256':result['sha256']})+'\n').encode())):
        fd,tmp=tempfile.mkstemp(prefix='.babel-wake-',dir=folder)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(body);stream.flush();os.fsync(stream.fileno())
            os.replace(tmp,path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return {**result,'state':'installed'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugin-dir',default=str(Path.home()/'.config/opencode/plugins'))
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    try:print(json.dumps(install(args.plugin_dir,apply=args.apply)))
    except (OSError,ValueError):parser.exit(2,'OpenCode plugin installation failed; preserve existing files for review.\n')

if __name__=='__main__':main()
