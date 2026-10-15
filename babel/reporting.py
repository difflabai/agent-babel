"""Local, opt-in typed reports. Never consumes native transcripts or credentials.

The local helpers expose stage_report/read_report. Only stage_report is filtered;
ordinary selected stage_message traffic and every remote webhook remain intact.
Event references must identify logical source events, not delivery attempts.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from babel.core import BridgeError

LOCAL_TOOLS = frozenset(("stage_report", "read_report"))
NOTIFY = frozenset(("completed", "failed", "blocked", "approval_required", "question", "experiment_transition"))
ROUTINE = frozenset(("progress", "tool", "subagent", "status"))
REPORT_ID = re.compile(r"report_[a-f0-9]{64}\Z")
MAX_RECORD_BYTES = 65536
MAX_NOTICE_BYTES = 2048
MAX_RECORDS = 4096
POLICY = {"version": 1, "local_report_tool": "stage_report", "local_detail_tool": "read_report",
          "notify": sorted(NOTIFY), "retain_locally": sorted(ROUTINE),
          "question_identity": "event_ref/revision/pending-or-resolved",
          "question_recipient": "Ember through existing permitted grants",
          "owner_approval_required": True,
          "instructions": "~/.config/255bits/agent-babel/WORKER-INSTRUCTIONS.md"}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def private(path, directory=False):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise BridgeError("Report storage refuses symlinked paths")
    info = path.stat()
    if (info.st_uid != os.getuid() or info.st_mode & 0o077
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))):
        raise BridgeError("Report storage requires owned private files")


def local_store(instance):
    """Keep selected details in the task workspace, never beside credentials.

    The working directory must belong to the same user. All newly created
    directories/files are private; existing modes are never weakened.
    """
    instance = Path(instance)
    private(instance, True)
    workspace = Path.cwd().resolve()
    if workspace.stat().st_uid != os.getuid():
        raise BridgeError("Use an owned task workspace for local report details")
    base = workspace / ".babel-reports"
    if base.is_symlink():
        raise BridgeError("Report workspace refuses symlinks")
    base.mkdir(mode=0o700, exist_ok=True)
    private(base, True)
    ignore = base / ".gitignore"
    try:
        fd = os.open(ignore, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        private(ignore)
    else:
        with os.fdopen(fd, "w") as stream:
            stream.write("*\n")
    root = base / hashlib.sha256(str(instance.resolve()).encode()).hexdigest()
    root.mkdir(mode=0o700, exist_ok=True)
    private(root, True)
    return root


def with_reporting_policy(instance, result):
    """Reach existing helper senders on their next successful tool response.

    This is advisory adoption guidance, not proof of model compliance. Never
    discard a successful delivery/receipt if the private cache is unwritable.
    """
    if not isinstance(result, dict):
        return result
    try:
        root = local_store(instance)
        with folder_lock(root) as folder:
            marker = folder / "policy-context-cli.json"
            if marker.exists() or marker.is_symlink():
                private(marker)
                if marker.stat().st_size <= 128 and json.loads(marker.read_text()).get("version") == 1:
                    return result
            else:
                fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w") as stream:
                    stream.write('{"version":1}\n')
                    stream.flush()
                    os.fsync(stream.fileno())
    except (OSError, BridgeError, ValueError):
        # A read-only workspace must not break existing selected-message tools.
        return result
    return {**result, "local_reporting_policy": POLICY}


@contextmanager
def folder_lock(root):
    root = Path(root)
    private(root, True)
    folder = root / "report-details"
    if folder.is_symlink():
        raise BridgeError("Report storage refuses symlinks")
    folder.mkdir(mode=0o700, exist_ok=True)
    private(folder, True)
    lock = folder / "lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        private(lock)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield folder
    finally:
        os.close(fd)


def bounded_text(data, name, limit, required=True):
    value = data.get(name)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > limit:
        raise BridgeError("Invalid or oversized report field: " + name)
    return value


def prepare(root, args):
    allowed = {"recipient", "conversation_id", "reply_to", "task_ref", "event_ref", "kind",
               "summary", "details", "revision", "question_state", "from_state", "to_state"}
    required = {"recipient", "conversation_id", "task_ref", "event_ref", "kind", "summary"}
    if not isinstance(args, dict) or set(args) - allowed or required - set(args):
        raise BridgeError("Missing or unsupported typed report fields")
    for name in ("recipient", "conversation_id", "task_ref", "event_ref"):
        bounded_text(args, name, 128)
    bounded_text(args, "reply_to", 128, False)
    summary = bounded_text(args, "summary", 32768)
    if "details" in args and (not isinstance(args["details"], str)
                              or len(args["details"].encode("utf-8")) > 49152):
        raise BridgeError("Explicitly selected report details exceed local capacity")
    kind = args["kind"]
    if not isinstance(kind, str) or kind not in NOTIFY | ROUTINE:
        raise BridgeError("Unknown report kind; classify explicitly before retrying")
    revision = args.get("revision", 1)
    if type(revision) is not int or not 1 <= revision <= 1000000:
        raise BridgeError("Report revision must be a positive bounded integer")
    phase = None
    if kind == "question":
        phase = args.get("question_state", "pending")
        if phase not in ("pending", "resolved"):
            raise BridgeError("Question state must be pending or resolved")
    elif "question_state" in args:
        raise BridgeError("Only question events may carry question state")
    if kind == "experiment_transition":
        bounded_text(args, "from_state", 64)
        bounded_text(args, "to_state", 64)
    elif "from_state" in args or "to_state" in args:
        raise BridgeError("Only experiment transitions may carry state changes")
    identity = [args["recipient"], args["conversation_id"], args.get("reply_to"),
                args["task_ref"], args["event_ref"], kind, revision, phase]
    mid = "report_" + hashlib.sha256(canonical(identity).encode()).hexdigest()
    record = {"schema_version": 1, "message_id": mid, **args, "revision": revision}
    if phase is not None:
        record["question_state"] = phase
    raw = canonical(record).encode()
    if len(raw) > MAX_RECORD_BYTES:
        raise BridgeError("Selected report record exceeds local capacity")
    with folder_lock(root) as folder:
        target = folder / (mid + ".json")
        if target.exists() or target.is_symlink():
            private(target)
            if target.stat().st_size > MAX_RECORD_BYTES:
                raise BridgeError("Stored report exceeds capacity; retain it for review")
            if target.read_bytes() != raw:
                raise BridgeError("Logical event changed; use a new event reference or material revision", 409)
        else:
            if sum(1 for p in folder.glob("report_*.json")) >= MAX_RECORDS:
                raise BridgeError("Local report capacity reached; retained reports were not pruned", 507)
            fd, temp = tempfile.mkstemp(prefix=".report-", dir=folder)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, target)
                dirfd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(dirfd)
                finally:
                    os.close(dirfd)
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)
    reason = "routine_" + kind if kind in ROUTINE else None
    if kind == "experiment_transition" and args["from_state"] == args["to_state"]:
        reason = "unchanged_experiment_state"
    notice = {"schema_version": 1, "kind": kind, "task_ref": args["task_ref"],
              "event_ref": args["event_ref"], "revision": revision,
              "summary": summary.encode()[:512].decode("utf-8", errors="ignore"),
              "details_ref": mid}
    if len(summary.encode()) > 512:
        notice["summary_truncated"] = True
    for name in ("question_state", "from_state", "to_state"):
        if name in record:
            notice[name] = record[name]
    text = canonical(notice)
    if len(text.encode()) > MAX_NOTICE_BYTES:
        raise BridgeError("Compact report notice exceeds capacity; selected details retained")
    staged = {"recipient": args["recipient"], "conversation_id": args["conversation_id"],
              "message_id": mid, "text": text}
    if args.get("reply_to") is not None:
        staged["reply_to"] = args["reply_to"]
    return staged, reason


def report_tool(root, tool, args, send):
    if tool == "read_report":
        if not isinstance(args, dict) or set(args) != {"message_id"} or not REPORT_ID.fullmatch(str(args["message_id"])):
            raise BridgeError("Read one exact local report ID")
        with folder_lock(root) as folder:
            target = folder / (args["message_id"] + ".json")
            private(target)
            if target.stat().st_size > MAX_RECORD_BYTES:
                raise BridgeError("Stored report exceeds capacity")
            return {"local_report": json.loads(target.read_text()), "notification_sent": False}
    if tool != "stage_report":
        raise BridgeError("Unknown local reporting tool")
    staged, reason = prepare(root, args)
    local = {"message_id": staged["message_id"], "details_ref": staged["message_id"], "policy_version": 1}
    if reason:
        return {"notification": "suppressed", "reason": reason, "local_report": local,
                "notification_sent": False}
    # Authentication, permission/route checks, approval, retry, rate/hop limits
    # and receipts remain entirely on the existing selected-message path.
    result = send("stage_message", staged)
    return {**result, "local_report": local}
