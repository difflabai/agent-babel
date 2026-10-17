"""One shared Grok receiver per account/native leader; no session services."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

from .account_wake import account, locked, read_json, write_json, Deferred, Receiver
from .grok_receiver import GrokNative


def ensure_receiver(account_file):
    account_file = Path(account_file).absolute()
    if account_file != Path.home() / '.config/255bits/agent-babel/trusted-account.json':
        return False
    root, _ = account(account_file)
    socket_path = Path(os.environ.get('GROK_HOME', str(Path.home() / '.grok'))) / 'leader.sock'
    native = GrokNative(socket_path)
    # Stock Grok lacks the reviewed control capability. Do not launch a polling
    # worker or infer readiness from a listening socket/registration response.
    native.loaded()
    key = [native.identity['socket_device'], native.identity['socket_inode']]
    try:
        with locked(root / 'grok-account-wake-start.lock') as fd:
            try:
                with locked(root / 'grok-account-wake-runtime.lock'):
                    pass
            except Deferred:
                path = root / 'grok-account-wake-runtime.json'
                if path.exists() and read_json(path, 4096).get('socket') == key:
                    return True
            script = Path(__file__).resolve().parent.parent / 'grok_account_wake.py'
            env = os.environ.copy()
            for name in ('GROK_SESSION_ID', 'CODEX_THREAD_ID', 'BABEL_SESSION_TOKEN'):
                env.pop(name, None)
            subprocess.Popen([sys.executable, str(script), '--account-file', str(account_file),
                              '--socket', str(socket_path), '--startup-fd', str(fd)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, pass_fds=(fd,), env=env, cwd=str(script.parent))
            return True
    except Deferred:
        return True


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account-file', required=True, type=Path)
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--startup-fd', required=True, type=int)
    args = parser.parse_args()
    receiver = None
    try:
        root, _ = account(args.account_file)
        startup = root / 'grok-account-wake-start.lock'
        from account_session_helper import private
        private(startup)
        if os.fstat(args.startup_fd).st_ino != startup.stat().st_ino:
            raise ValueError('Receiver startup context mismatch')
        deadline = time.monotonic() + 120
        while True:
            try:
                with locked(root / 'grok-account-wake-runtime.lock'):
                    receiver = Receiver(args.account_file, args.socket, client='grokbot', native_factory=GrokNative)
                    receiver.native.loaded()
                    identity = receiver.native.identity
                    write_json(root / 'grok-account-wake-runtime.json',
                               {'pid': os.getpid(), 'socket': [identity['socket_device'], identity['socket_inode']]})
                    os.close(args.startup_fd)
                    while True:
                        try:
                            receiver.tick()
                        except Exception:
                            current = args.socket.stat()
                            start = Path('/proc', str(identity['pid']), 'stat').read_text().rsplit(')', 1)[1].split()[19]
                            if (current.st_dev != identity['socket_device'] or current.st_ino != identity['socket_inode'] or start != identity['start']):
                                return
                        time.sleep(2)
            except Deferred:
                if time.monotonic() >= deadline:
                    return
                time.sleep(.25)
    except (Exception, KeyboardInterrupt):
        return
    finally:
        if receiver is not None:
            receiver.close()
