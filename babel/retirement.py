"""Retire terminal, inactive threads without deleting history or dedup records.

Caller holds the Store transaction for sweeps. Replies and sweeps therefore
serialize across processes using SQLite's writer lock.
"""


def initialize(db):
    columns = {row[1] for row in db.execute("PRAGMA table_info(messages)")}
    if "retired_at" not in columns:
        db.execute("ALTER TABLE messages ADD COLUMN retired_at REAL")
    db.execute("CREATE INDEX IF NOT EXISTS thread_messages ON messages(root_id)")
    db.execute("CREATE INDEX IF NOT EXISTS active_messages ON messages(retired_at,seq)")
    db.execute("CREATE INDEX IF NOT EXISTS message_activity ON events(message_id,action,created)")


def active_count(db):
    return db.execute("SELECT COUNT(*) FROM messages WHERE retired_at IS NULL").fetchone()[0]


def usage(db):
    active = active_count(db)
    total = db.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    return {"active_messages": active, "retired_messages": total - active, "total_messages": total}


# Read/export/claim/poll activity deliberately does not extend thread lifetime.
# Approval and receipt timestamps live on messages; cancellation is an audit event.
ELIGIBLE = """
    SELECT m.root_id, COUNT(*) AS messages
    FROM messages m WHERE m.retired_at IS NULL
    GROUP BY m.root_id
    HAVING SUM(m.status NOT IN ('acknowledged','canceled')) = 0
       AND MAX(MAX(m.created, COALESCE(m.approved, 0), COALESCE(m.acknowledged, 0),
           COALESCE((SELECT MAX(e.created) FROM events e
                     WHERE e.message_id=m.id AND e.action='canceled'), 0))) <= ?
"""


def retire(db, now, idle_seconds, dry_run=False):
    cutoff = now - idle_seconds
    eligible = db.execute(
        "SELECT COUNT(*), COALESCE(SUM(messages),0) FROM (" + ELIGIBLE + ")",
        (cutoff,)).fetchone()
    if not dry_run and eligible[0]:
        db.execute("UPDATE messages SET retired_at=? WHERE retired_at IS NULL "
                   "AND root_id IN (SELECT root_id FROM (" + ELIGIBLE + "))", (now, cutoff))
    return {"dry_run": dry_run, "idle_days": idle_seconds // 86400,
            "inactive_before": cutoff, "eligible_threads": eligible[0],
            "eligible_messages": eligible[1], **usage(db)}
