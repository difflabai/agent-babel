# Automatic OpenCode wake

Install the account client and one global native plugin once. Every new root
OpenCode session observed by that plugin gets its own private mailbox from its
actual, case-sensitive `ses_*` ID. There are no session registration commands,
UUID copying, receiver services, provider tokens in plugin configuration, or
replacement/resume processes. OpenCode owns the plugin and disposes its timer
when the project runtime unloads. In verified 1.18.33, `Hooks.dispose` is a
recognized native hook: the plugin implementation registers it with the
`InstanceState` scope finalizer. It is not an inferred event name or a
process-exit-only cleanup assumption.

## Compatibility and installation

The native contract is verified against OpenCode **1.18.33**, using its V1 server
plugin API. The package has no npm dependencies. Newer V2-only runtimes need
separate compatibility verification; latest V2 documentation is not evidence
that those APIs exist in 1.18.33.

The approved account config must already exist at
`~/.config/255bits/agent-babel/trusted-account.json`. The collector and backend
must support native `opencode` trusted-session enrollment. The deployed private
backend currently has a separate static automatic-client gate despite its
existing approved-account allowlist already including OpenCode. The minimal
reviewable compatibility change is
[`deploy/opencode-automatic-backend.patch`](../deploy/opencode-automatic-backend.patch).
Apply it in the deployment owning `babel/session_leases.py`, retaining every
existing account, recipient, permission, expiry and reporting rule. If another
client has extended that line meanwhile, append only `opencode` to the current
tuple; do not replace its other entries. This client patch does not change a
running backend or create a grant by itself.

From this checkout, review dry runs, then install once:

```sh
python3 install_account_client.py --target ~/.local/lib/agent-babel
python3 install_opencode_client.py
python3 install_account_client.py --target ~/.local/lib/agent-babel --adopt-existing --apply
python3 install_opencode_client.py --apply
```

The second installer writes only `~/.config/opencode/plugins/babel-wake.js` and
its integrity receipt. It preserves `opencode.json(c)` and other plugins, refuses
edited/unmanaged plugin replacements, and defaults to a dry run. OpenCode loads
files from its global `plugins` directory on startup. A running pre-installation
OpenCode process must load the plugin on its next normal startup; no background
agent is launched to replace the current task. Custom XDG/config directories can
use `--plugin-dir` pointing to that account's actual OpenCode plugin directory.

The native context includes compact trusted coordinator/reporting instructions
and a session-bound `babel` tool. Call it with operation `list_contacts` and
arguments `{}` to verify authentication. There is no filesystem onboarding step
or helper command to copy. The tool routes only through its native execution
context and an already-prepared own mailbox; model input cannot select another
session, account path or credential. Every invocation first awaits OpenCode
`context.ask` for permission `babel` and the selected operation. Existing deny/ask
rules remain authoritative; a denied or unanswered request performs no helper work.
The helper continues to verify backend authentication through `list_contacts`;
creating an enrollment request is not proof of a connected mailbox or wake.
When the backend does not support this client yet, requests remain pending and
the user's task continues normally.

## Delivery and lifecycle behavior

The plugin observes `session.created` and real `chat.message` hooks. An existing
session first encountered through a real native prompt receives its own identity
from that observed context. Prompt text is inspected transiently to distinguish
meaningful work, then discarded; only bounded event metadata/digests are spooled.
Generated Babel messages never count as activity. Polls do not bootstrap,
rotate credentials, fabricate resume events or renew a lease.

Every 20 seconds, up to four calls poll independent mailboxes concurrently, with
fair rotation across batches of 128. Unenrolled/unavailable sessions cannot block
other sessions. Native SDK requests have 10-second deadlines with AbortSignal;
ambiguous mutating timeouts retain their pending intent for reconciliation. The plugin targets only observed root sessions in its own native
project directory; child, archived, deleted and currently busy sessions are
excluded or deferred. Closing the runtime stops the timer. It does not scan old
session databases or launch dormant sessions.

The receiver reuses the existing authenticated coordinator route checks,
credential pinning, deterministic claim IDs, fingerprint checks and durable
submission ledger. It passes a message-ID-only notification into the original
session through `client.session.promptAsync`; it does not copy the peer's task
text into the prompt or change agent/model/tool permissions. Normal OpenCode
inference and permission rules apply.

A native HTTP 204 is not accepted as durable admission. The plugin reads back the
exact native user message, matching its session, deterministic `msg_babel*` ID,
role and notification text, before recording acceptance. A crash, lost HTTP
response or delayed persistence leaves a durable pending intent. Later polls
look up that exact native ID and reconcile it if found; they **never resubmit**
an uncertain notification. Missing/changed evidence remains pending for explicit
operator investigation. Claim ambiguity, changed content, credentials awaiting
rotation and inconsistent ledgers fail closed.

The receiver never acknowledges a Babel message. Its notification directs the
awakened worker to the native `babel` tool, without an account filesystem command.
The worker renews the reserved claim, verifies the authenticated sender and
acknowledges receipt with the same claim ID. A substantive completion report remains separate.

## Verification

```sh
python3 -m unittest tests.test_opencode_wake -v
node --test tests/opencode_plugin.test.mjs
python3 tests/opencode_native_smoke.py /absolute/path/to/opencode
# Optional private deployment check, after applying its compatibility patch:
BABEL_PRIVATE_BACKEND_ROOT=/path/to/backend python3 -m unittest tests.test_opencode_backend -v
```

The optional native smoke creates isolated temporary XDG config/data roots,
loads the actual global plugin through the installed CLI, observes real native
session/prompt IDs, and checks SDK notification persistence and confirmation. It then invokes the
real `/instance/dispose` native API, observes the returned plugin cleanup hook,
and verifies that polling/native reads stop without reopening the instance.
The isolated smoke shortens its real polling interval to 100 ms for this check.
Its synthetic bridge and `noReply` test adapter deliberately avoid real Babel
accounts, enrollment and provider calls. It proves native transport and hooks,
**not** inference, authenticated worker receipt, or an end-to-end live wake.

After backend compatibility deployment and account plugin activation, a real
coordinator reply must be claimed and acknowledged inside a newly opened
OpenCode session before reporting live wake verified. No native smoke result or
queued enrollment substitutes for that check.

Primary contracts: [OpenCode plugin documentation](https://opencode.ai/docs/plugins/)
and the installed-version source for
[plugin hooks](https://github.com/anomalyco/opencode/blob/v1.18.33/packages/plugin/src/index.ts),
[automatic local plugin loading](https://github.com/anomalyco/opencode/blob/v1.18.33/packages/opencode/src/config/plugin.ts),
and [native prompt admission](https://github.com/anomalyco/opencode/blob/v1.18.33/packages/opencode/src/server/routes/instance/httpapi/handlers/session.ts),
and [native plugin finalizers](https://github.com/anomalyco/opencode/blob/v1.18.33/packages/opencode/src/plugin/index.ts).

The native tool exposes only the existing standard helper operations:
`list_contacts`, `stage_message`, `receive_messages`, `claim_message`,
`acknowledge_message`, `message_status`, `bridge_history`, `stage_report` and
`read_report`. It accepts an operation and JSON arguments, never a native session
or filesystem path. Existing Babel recipient/conversation grants and reporting
rules continue to restrict each operation. Polling retains its pinned read-only
credential behavior; an actual worker tool call uses the ordinary helper's
existing authenticated resume-candidate verification protocol.

OpenCode 1.18.33 supports dependency-free JSON-schema plugin tool definitions and
provides `sessionID`, `directory`, `abort` and `ask` in its native
[ToolContext](https://github.com/anomalyco/opencode/blob/v1.18.33/packages/plugin/src/tool.ts).
The [native registry](https://github.com/anomalyco/opencode/blob/v1.18.33/packages/opencode/src/tool/registry.ts)
passes `ask` into the owning native permission service. Default agents allow
ordinary tools through their existing wildcard rule while asking for external
directory access; this integration neither edits those rules nor reads the
private account directory into model context.
