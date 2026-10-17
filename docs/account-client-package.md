# Account-local lifecycle client package

This is the opt-in client code used by the existing approved Pop!_OS trusted-account
deployment. The client keeps one native session's local identity/evidence and
talks through its existing authenticated helper. The server must already implement
the matching trusted-account protocol. Canonical server installations without that
backend do not gain automatic enrollment by installing this package.

On an account whose Codex lifecycle integration is already installed and trusted,
new sessions also become eligible for automatic mailbox wake delivery. Opening a
session is the only session-level action: no registration command, copied UUID,
service template, or session-specific watcher is required. A shared receiver runs
automatically alongside the existing native Codex runtime and discovers the
runtime's loaded threads. The receiver is background execution owned by the
integration; it is not an additional systemd service.

The trusted UNIX identities remain exactly `mikkel@pop-os` and `work@pop-os`,
validated against the executing UID. Native context, reviewed legacy bindings,
credential rotation/recovery, meaningful-work classification and reporting policy
retain their installed behavior. These are trusted local assertions, not provider
attestation. Hosted Claude and unsupported native contexts remain rejected.

## Source and scope

The prior lifecycle distribution was an 80-file source archive installed on
2026-10-08 (archive SHA-256
`b1610af039813febc64f296c0c3d14afc14b4f8c0dea9a12d17b753ce5405a1e`).
It had no maintained client installer in canonical main. The client-only source
here reuses the reviewed local fast-hook revision `5570a3e`:

- `account_lifecycle_hook.py`, `babel/lifecycle_dispatcher.py` and
  `babel/prompt_intake.py` contain the fast entrypoint and completion consumer.
- `babel/native_lifecycle.py` retains the installed native event parser.
- Existing `account_session_helper.py`, `babel/account_bootstrap.py` and
  `babel/reporting.py` supply the necessary client prerequisites. The helper's
  two backend constant imports now come from the client context module, with
  the same peer allowlist and native event regex.
- `babel/account_wake.py`, `babel/native_receiver.py` and `account_wake.py`
  provide automatic Codex mailbox discovery and the shared native receiver.

Server enrollment, session leases, collector/operator, legacy admission, channels,
policy, authentication and transport implementations are excluded from this change.
The old global-instruction `install-user.py` is a different installer for the
`babel-instance` helper and is not used here.

## Install or upgrade code

Use a reviewed, pinned repository revision or release archive. Python 3.10+ and
the standard library suffice on Linux. Plan against an explicit owned private
target first:

```sh
python3 install_account_client.py --target "$HOME/.local/lib/agent-babel"
```

The default is read-only. Review the file list and bundle digest, then add
`--apply` to install that code. For the first adoption of a previously unmanaged
bundle whose client files differ, review those differences and use
`--adopt-existing` with the same target. That flag is not a source-drift override
for an already managed package: edited managed files always require reconciliation.

The manifest includes every fast-path and completion module. Libraries are installed
before the entrypoint. Existing private `babel/core.py` and `babel/__init__.py` are
preserved; fresh client-only targets receive the canonical error/validation support
files. No gateway, auth, policy, lease or channel file is installed. The installer
records exactly which support files it owns so subsequent upgrades remain complete.

Source files keep their existing private modes. Each installation retains the old
managed source and receipt in `.account-client-backups/<unique-id>/`, writes a new
`.account-client-install.json` with file hashes, and refuses symlinks, foreign or
publicly accessible destinations, missing release files, source drift and concurrent
installers. A caught installation failure restores the old entrypoint and changed modules;
independent edits are retained for manual reconciliation. Backups contain source
only. They are not backups of account state, tokens or server data.
An abrupt process/machine termination during the multi-file installation requires
inspection and recovery from that snapshot; atomic file replacement is not a
transaction across the whole directory.

The installer neither reads nor writes account configuration, credentials, hook
settings, native bindings, services or webhooks. It does not invoke any runtime
callback. Runtime behavior begins when the existing trusted lifecycle hook invokes
the installed code. Installation is separate from hook activation and server
deployment.

## Automatic Codex wakes

The existing trusted Codex lifecycle hook ensures one shared account receiver is
running. A process lock prevents competing receiver launches. There is no separate
session-registration file or registration API. The receiver discovers loaded thread
IDs from the existing local Codex app server, then matches each ID to its existing
deterministic account mailbox or an exact, previously reviewed legacy binding.
It does not enroll a new mailbox, adopt a similarly named session, create a
credential, broaden a conversation grant, or produce lifecycle activity from polls.

The receiver uses the account's existing private native control socket. It verifies
the socket's UNIX peer and uses bounded, standard-library WebSocket metadata calls.
It does not start or resume Codex threads. A thread must already be loaded and
eligible in the native runtime before a notification can be queued. The shared
receiver stops when that runtime disappears; a later real lifecycle hook can start
it again. One unavailable mailbox is isolated from the other loaded sessions.

Messages remain scoped to each session's existing authenticated mailbox. The
receiver reserves a recipient claim before using the native queue, and the wake
notification carries that exact claim ID. The receiving agent must renew it,
read the authenticated sender, and acknowledge receipt with the same ID before
handling the message under its existing authority. Native queue acceptance is not
proof of model wake, receipt, or task completion.

Delivery intents and accepted notifications are recorded durably per mailbox.
An interrupted claim or uncertain native submission quarantines that mailbox's
delivery state instead of automatically submitting another notification after a
restart. Keep retained ledgers for reconciliation. Pending enrollment, credential
rotation and unsupported native contexts are left alone. Claude lifecycle tracking
retains its existing behavior; this automatic native wake path is for Codex.

An already trusted account needs only the one package upgrade. Future supported
Codex sessions use that integration automatically. A fresh account still requires
the existing approved account configuration, enrollment backend and native hook
trust review; copying this code does not authorize those operations.

For an account currently using individual session watchers, validate the new
receiver with a real coordinator message and a claimed/acknowledged reply before
explicitly retiring those watchers. Do not run two adapters against the same
mailbox during the canary. Preserve old delivery ledgers, including uncertain
intents; do not delete them to force a retry or treat a pending native queue as a
completed handoff. Code installation does not stop old watchers or modify their
services.

The [Codex app-server documentation](https://learn.chatgpt.com/docs/app-server)
describes loaded-thread discovery and metadata reads; the
[CLI reference](https://learn.chatgpt.com/docs/cli/reference) describes queueing
to an existing thread. Hook output alone cannot wake an idle turn: the
[hooks documentation](https://learn.chatgpt.com/docs/hooks) says background hook
output waits for the next user turn when no turn is active. That is why the
account integration needs the automatic shared receiver.

## Hooks and recovery

The [Claude](../deploy/account-claude-hooks.example.json) and
[Codex](../deploy/account-codex-hooks.example.json) examples describe existing
approved callback entrypoints. They are inert examples; the installer does not
merge them into settings, bypass native hook review, or create `trusted-account.json`.
Existing account configuration and reviewed mappings remain at their existing paths.

Claude prompt intake is [fast and local](fast-claude-prompt-hook.md). After successful
intake, kernel-buffered atomic metadata survives hook/native process exit within the
same OS boot. It remains pending until a correlated completion arrives or later
input supersedes the pending prompt. Without completion there is no fabricated
completed-work event, lease renewal, background recovery task or transcript read.
Completion commits eligibility before removing retry records and retains stable
deduplication. After reboot, unfinished eligibility and old-boot intake are discarded
conservatively; completed history stays intact. Prompt intake is deliberately not
power-loss durable, and no completion callback means the abandoned work is not
reconstructed automatically.

The regression suite includes independent hook processes, interrupted intake,
completion/cleanup retries, boot fencing, bounded/coalesced journals and a fresh
package install with separate prompt and completion processes. Tests use synthetic
owned roots and do not launch a real Claude/Codex model, kill a native session, or
reboot a machine.
