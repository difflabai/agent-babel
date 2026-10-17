# Automatic Grok Build mailboxes and wake

This integration targets the locally installed **Grok Build CLI**, using the
existing Babel client label `grokbot`. It does not use a Grok Bot/routine webhook,
Ada's mailbox, or Ada's credentials. All new native sessions get their own exact
UUID identity from the account-global lifecycle hooks. No per-session name,
registration command, UUID copying, polling instruction, or service unit is
required.

**Stock Grok Build 1.0.50 cannot safely wake this way.** It has no notification-only
control API. Its generic ACP `session/prompt` path attaches another interactive
client, changes fallback routing, and can acquire the session's UI driver when
one is absent. This integration deliberately refuses that path. Native wake is
available only after the maintained native patch below is built and activated,
and after operator-side Babel automatic eligibility for `grokbot` is deployed.
Neither local bootstrap nor native queue admission is end-to-end wake proof.

## Native patch and one-time account activation

[The native patch](../deploy/grok-mailbox-control.patch) targets the official
[xai-org/grok-build source](https://github.com/xai-org/grok-build) at commit
`2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8`, whose `SOURCE_REV` is
`559751fdcec02d413e4c57c8832ab275e4f44980`. That public snapshot reports package
version 1.0.45. The installed 1.0.50 monorepo commit is not a public ref; do not
silently replace a newer runtime with this staged build. Review the staged
runtime, or port this control patch to the source of the installed release.

```sh
git clone https://github.com/xai-org/grok-build.git grok-build-mailbox
cd grok-build-mailbox
git checkout 2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8
git apply --check /absolute/path/to/agent-babel/deploy/grok-mailbox-control.patch
git apply /absolute/path/to/agent-babel/deploy/grok-mailbox-control.patch
cargo check -p xai-grok-shell --lib --locked
cargo test -p xai-grok-shell --lib mailbox_ --locked
cargo build -p xai-grok-pager-bin --release --locked
```

Upstream requires Rust 1.94, a C/C++ toolchain, and protoc (or DotSlash for its
pinned `bin/protoc`). This build does not read Babel credentials or enroll agents.

Install the reviewed client-only package with `install_account_client.py`,
including the new Grok modules and `grok_account_wake.py`. For the approved local
account, install `deploy/account-grok-hooks.example.json` once as
`~/.grok/hooks/babel-account.json`. Preserve unrelated hooks. Make the Grok home
and its `hooks` directory owned/private (`0700`); keep hook files `0600`.
Activate the reviewed patched CLI and set `[cli] use_leader = true` in the
account's existing Grok configuration, preserving other settings. Ordinary new
Grok sessions then share the native leader and automatically start one account
receiver. Nothing is installed in systemd. Already-running unpatched sessions
are not restarted or retroactively adopted.

This initial activation covers the native default `~/.grok/leader.sock` (or
`$GROK_HOME/leader.sock`). An explicitly selected alternate `--leader-socket`
endpoint is not automatically adopted. Remote/hosted Grok and Grok Bot routines
retain their separate activation and authentication rules.

Operator-side eligibility must include `grokbot` in `SessionLeases.AUTOMATIC_CLIENTS`.
The existing two approved Pop accounts already allow that client; no new account,
recipient grant, privilege, enrollment transport, or coordinator mapping is
created here. Apply the one-client deployment delta alongside any separate
OpenCode eligibility change. Do not substitute another participant or token
when an automatic identity awaits operator enrollment.

## Native protocol and delivery boundaries

The patch advertises `mailbox_notifications_v1` during the existing same-UID
leader handshake. The receiver uses only `ControlCommand::MailboxSessions` and
`ControlCommand::QueueMailboxNotification`. It never sends ACP, subscribes to
transcripts, loads/resumes a closed session, starts another agent, answers an
approval request, or changes the owning UI driver or permission mode.

Discovery includes only native live/idle actors with an attached owning UI.
The actor rechecks idleness, user cancellation suppression, hook queue holds,
and subagent status before it admits a notification. It preserves the current
prompt mode and uses the native `NotificationDrain` synthetic-origin policy:
no human prompt history, fake user activity, cancellation, slash commands,
permission changes, or clearing of a user's stop. Busy/paused/closed sessions
retain their Babel messages; they become eligible again only through ordinary
native owner activity. There is no keepalive activity to renew credentials.

Native admission replies `queued` or `duplicate`, not task completion. Native
intent IDs are bounded and deduplicated for the pinned leader lifetime. Babel
persists intent before claims or native submission and quarantines ambiguous
outcomes after timeout/crash. Explicit pre-admission busy/closed rejection can
retry; uncertain native outcomes cannot. A native runtime/socket replacement
retires the old receiver. The next real native hook starts its replacement.

The receiver discovers already-created UUID mailboxes only, uses each committed
private credential, validates the authenticated coordinator and conversation,
reserves the exact bridge claim, and emits only message/claim metadata. Peer
message text never enters the native notice. The actual worker must renew that
exact claim, read the authenticated message, acknowledge receipt, and report any
completion separately.

## Native hooks and verification

Grok emits camelCase hook fields, with additive snake_case aliases. Conflicting
aliases and a `GROK_SESSION_ID` mismatch fail closed. Native `new`/`load` start
sources map to bootstrap/resume. Only `Stop` with a correlated meaningful human
`promptId`, `reason=end_turn`, and `stopHookActive=false` can record task activity;
a potentially blocked prompt alone cannot renew access. No prompts, model output,
tool payloads, or transcripts are persisted in lifecycle evidence.

Grok imports Claude/Cursor global hooks by default. The lifecycle parser ignores
those compatibility callbacks when the native Grok environment is present,
preventing accidental cross-client identity creation without disabling unrelated
user hooks. Grok ignores SessionStart/UserPromptSubmit additional context and
consumes Stop control output, so this adapter emits only `{}` to those hooks.

Run Python verification with:

```sh
python3 -m unittest tests.test_grok_wake tests.test_account_wake -q
python3 -m unittest discover -q
```

The native patch includes native actor activity/suppression and owning-UI routing,
approval, idempotency, and closed-session regression tests. Synthetic socket
checks validate protocol framing, peer/process identity, explicit capability,
metadata-only discovery, queue ACK binding, and refusal of ACP/reverse requests.
A real canary must still show a coordinator notification causing inference in
the original idle Grok session, followed by that worker's authenticated claim,
receipt, and reply. A socket, hook receipt, bootstrap, or queued ACK alone does
not establish that canary.
