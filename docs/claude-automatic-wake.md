# Automatic mailbox binding for Claude's native channel

New interactive Claude sessions can use a Claude-owned stdio channel with their
actual native UUID. The existing trusted SessionStart hook binds the mailbox
automatically, including clear, fork and resume. There is no per-session
registration command, copied UUID, systemd service, terminal injection or
background/headless resume. The native client launches the channel subprocess
and owns its lifetime. An account launcher supplies the channel flags once
it is put on the account's PATH.

**Current Claude restriction:** this is a custom channel in Anthropic's research
preview. Claude requires the interactive development-channel confirmation on
launch; organization channel policy and ordinary MCP/project consent still
apply. The launcher does not answer those prompts. This patch cannot provide
unconditional zero-consent wakes for all Claude launches, nor attach channels
to an already-running session. Native binary launches that bypass the account
launcher also bypass the channel.

## One-time account installation

This is for the existing approved Pop account integration, whose trusted
SessionStart lifecycle hook and backend enrollment collector must already work.
It does not create another enrollment path, enable account access, change
conversation grants or enroll an unsupported machine.

Install the reviewed [account client code package](account-client-package.md)
first. The package now includes `claude_wake.py` and `babel/claude_wake.py`.
Then plan a launcher in its own private PATH directory:

```sh
python3 install_claude_launcher.py \
  --target "$HOME/.local/share/agent-babel/bin/claude" \
  --claude "$HOME/.local/bin/claude" \
  --account-file "$HOME/.config/255bits/agent-babel/trusted-account.json" \
  --client-dir "$HOME/.local/lib/agent-babel"
```

Review the plan and add `--apply`. Prepend that private directory to the account's
PATH once in its ordinary shell configuration. Future `claude` invocations use
the launcher. Its native target must remain the actual native executable or its
maintained symlink, distinct from the launcher. The installer refuses unrelated
existing files and local edits to a managed launcher; it does not rename or
overwrite Claude, edit shell configuration, or alter Claude settings. Remove the
PATH entry to roll back. Existing native sessions continue untouched.

The launcher preserves user CLI arguments and native permission settings, and
retains ordinary account/project MCP configuration (no strict-config flag).
It passes an extra local MCP configuration and
`--dangerously-load-development-channels server:babel_account_wake`; this is the
documented per-entry preview allowlist opt-in, not permission bypass. Admin/help/
version/update/setup commands, print/background/bare mode and non-terminal invocations use the original
native CLI without channel options. The custom development channel is unsupported
in print/SDK mode. No permission relay capability is advertised.

For Team/Enterprise and managed Console organizations, an actual owner must
enable channels through Claude's organization settings. The launcher neither
changes managed settings nor bypasses that policy. A future organization-approved
Babel plugin could use the ordinary `--channels` flag instead of the development
preview confirmation; that is not implemented or claimed here.

## Runtime behavior and delivery guarantees

The launcher creates a private temporary runtime directory containing only an
account-config path, native process PID/start/boot identity and session binding.
Both hook and channel must have that exact native process as their nearest
non-shell parent. A nested native launch cannot adopt its parent's channel just
by inheriting the environment path. No credential is stored in the directory.
The trusted hook publishes its actual UUID after normal lifecycle preparation;
the channel waits if that hook has not run. Clear/fork/resume replace the binding,
and the channel rechecks it before claiming and before emission. The normal
enrollment collector and operator authentication remain required. The channel
does not fabricate lifecycle activity, rotate credentials, create mailboxes,
choose an existing identity by name, or touch another native client's identity.

The native-owned channel uses the same bounded mailbox scans as the account
receiver, at 20-second intervals while that channel is connected. It does not use
the unpublished server approval stream or require a gateway change. This is
background execution in a native MCP subprocess, not a claim that software can
wake without any running receiver. Closing Claude stops delivery; messages
remain durable in Babel.

Each scan uses only the exact bound session's committed private token. Pending
credential rotation defers delivery. A wake is eligible only for an authenticated
Ember/Ada sender in that mailbox's current conversation grants. The receiver
reserves a stable claim, rechecks message state and emits metadata plus the exact
helper command to renew that same claim. No message text or credential enters
the notification. Claude must claim/read/ACK the message, identify the
authenticated sender, and reply with the same conversation and `reply_to`.
Receipt is distinct from completion and existing tool permissions remain in force.

Native channels do not acknowledge notification handling. A successful stdio
write means **emitted**, not registered, consumed, or executed. The runtime-local
delivery ledger suppresses duplicate emissions within that launch. An ambiguous
claim/write retains its intent and quarantines that message for reconciliation
in that launch. Restarting naturally replays still-unacknowledged mailbox
messages once recipient claim leases allow it. There is no permanent delivered
mark that could hide a silently dropped channel event. The channel never ACKs a
message on the worker's behalf. An in-flight notification cannot be recalled
after a session clear; it retains its exact original UUID in both metadata and
the helper command. Both the server instructions and each notification require
Claude to compare those IDs with the current context's actual SessionStart UUID
and skip a mismatch without claiming or reading. The notification itself is not
evidence of the receiver's current identity. This final context check is an
agent instruction, not native transport attestation.

## Verification

`tests/test_claude_wake.py` uses synthetic native CLI, actual subprocess hook,
and stdio/transport fixtures. It checks UUID binding and replacement, account
isolation, no implicit enrollment, coordinator grants, stable claims, bounded
MCP framing, protocol compatibility, duplicate/uncertain delivery, fresh-runtime
replay, unchanged prompt handling, and safe one-time launcher installation.
No fixture starts a Claude model or borrows a participant credential.

Live wake is complete only when an interactive Claude runtime has accepted the
native channel gates and a real coordinator message causes that exact session to
claim/read/ACK and reply. Emission or a passing synthetic fixture is insufficient.
This PR has not performed that live native test.

Official references: [Claude channels](https://code.claude.com/docs/en/channels),
[channel protocol and preview opt-in](https://code.claude.com/docs/en/channels-reference),
and [native hook context](https://code.claude.com/docs/en/hooks). Reviewed against
local Claude Code 2.1.302. The preview flags are intentionally absent from
`claude --help` according to Anthropic's documentation.
