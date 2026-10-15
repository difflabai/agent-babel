# Fast Claude prompt intake

`UserPromptSubmit` records only the native session/optional turn ID, a meaningful
prompt boolean, and local observation order in the account's private automatic
spool. Prompt text is never stored. This entrypoint does not import the HTTP,
credential helper or SQLite stack, take lifecycle/credential locks, replay pending
events, bootstrap enrollment, rotate credentials, contact a service, or launch a
background process. Hook timeout settings stay unchanged.

Completion processing consumes the atomically published metadata under the existing lifecycle
lock before correlating a Claude final response. Activity is still queued only by
that normal completion path, with its existing deduplication, timestamps, trusted
account/native bindings and credential handling. Codex lifecycle behavior is
unchanged. Reviewed legacy instances keep their existing credential and database
locations; prompt intake uses the native session's existing automatic spool.

Claude prompts without a turn ID coalesce to the latest observation; explicitly
identified turns retain their first eligibility record. Late records cannot lend
a completed prompt to a later turn. Small interrupted records invalidate uncertain
eligibility rather than borrowing earlier meaningful work. Intake is bounded;
capacity failures fail closed until completion processing recovers the queue.

The prompt path does not call `fsync`: a blocked home filesystem must not block
submission. Kernel-buffered records survive hook process exit; completion commits
eligibility and events durably using the existing SQLite path. Records carry an
OS boot binding. After a reboot (or the first upgrade from the old protocol),
unfinished eligibility is conservatively cleared before consuming new boot-bound
records; finished IDs and durable event history remain intact. This prevents lost
pre-crash invalidations from lending an old real prompt to a later notification.

An empty, truncated, invalid or oversized published prompt record makes the
affected completion ineligible, including when the record's boot is unreadable.
The consumer first commits that decision for all unfinished eligibility, retaining
finished IDs/events, then removes the corrupt record. A fresh prompt can proceed;
bad content does not permanently block completions or roll back boot recovery.
Ownership, private modes and symlink checks still reject unsafe paths. Unexpected
private filenames require reconciliation rather than automatic deletion.

A lightweight per-session marker emits the existing reporting advisory once.
Existing sessions may receive that advisory once again after upgrading. The
marker is advisory metadata and never grants access or renews a lease.

The [account-client installer](account-client-package.md) ships all seven client
modules together, installs libraries before switching the entrypoint, preserves
existing backend files, and records source hashes and a rollback snapshot. It
never installs hooks, changes settings, enrolls an account, contacts a service,
or restarts native sessions. Existing approved hooks load the new code on their
next callback. The server's trusted-session backend remains a separate prerequisite.

Existing conservative limits remain: wall-clock-first observation order may reject
work after a clock correction; a `.pending` writer observed by completion makes
that completion ineligible; and the 8192-event/turn evidence cap stops admission
rather than deleting deduplication history. This recovery repair does not change
those boundaries. Corrupt journal decoder recursion errors follow the same
ineligible-and-remove path; deeply nested native hook input remains a separate
input-hardening concern. Installer process/machine termination recovery is described
in the package guide and still requires inspecting its source-only snapshot.
