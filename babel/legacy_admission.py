"""Fence unattended schema1 admission; explicit private policy edits are separate."""
import os
import sqlite3
from pathlib import Path
from .core import BridgeError

PINNED_ACCOUNTS = Path('/etc/agent-babel/trusted-accounts.json')


def assert_legacy_admission(existed, db_path, *, env=None, accounts_path=None):
    # Existing private reconnect validation still checks state/digest/grants.
    # This does not authenticate a mailbox or renew an idle lease.
    if existed:
        return
    env = os.environ if env is None else env
    marker = PINNED_ACCOUNTS if accounts_path is None else Path(accounts_path)
    enabled = bool(env.get('BABEL_TRUSTED_ACCOUNTS_FILE')) or marker.exists() or marker.is_symlink()
    path = Path(db_path)
    if not enabled and path.exists():
        # Read-only: never create/migrate a database during admission validation.
        # Any durable lease table keeps the guard after flag removal/rollback.
        try:
            db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)
            try:
                enabled = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='trusted_sessions'").fetchone() is not None
            finally:
                db.close()
        except sqlite3.Error:
            raise BridgeError('Cannot verify legacy admission lifecycle guard', 503) from None
    if enabled:
        raise BridgeError('New schema1 automatic admission is disabled; use trusted-session schema2 bootstrap', 403)
