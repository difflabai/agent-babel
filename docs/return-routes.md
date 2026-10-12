# Explicit return routes for existing mailboxes

This host-only command adds one reverse route to an existing authenticated
mailbox. It has no public RPC, enrollment path, credential generation, lifecycle
renewal or native wake setup. Automatic contexts retain their outgoing-only
default. The supplied conversation must already allow recipient → sender.
Both endpoints must be active and have the same explicit owner.

The command works with all client labels accepted by the participant policy,
including `grokbot` (Grok), `opencode`, `codex`, `claude`, `cursor`, `dots` and
`muse`. It uses only identities and conversations that already exist:

- New automatic Codex/Claude/Cursor mailboxes use their existing dynamic
  reporting conversation; no collision-prone entry is added to `agents.json`.
- Account-proven migrated Grok/OpenCode and other leased legacy mailboxes
  retain their original static identity and reporting conversations.
- Existing static mailboxes retain their configured acceptance, activation,
  owner, expiry, revocation and OAuth/static authentication requirements.

New native Grok/OpenCode adapters remain unsupported by the existing lifecycle
implementation. This command does not create one or infer a native context.
Use the authenticated `grokbot` ID, never substitute a display name or `grok`.

For a leased recipient, `--accounts-file`, `--peer` and `--native-id` are
required and must match its durable account/client/context binding. The decision
captures its current credential generation and lease deadline. It cannot renew
the lease, follow a rotated credential generation, or extend itself when later
activity renews the underlying session. At the exact captured deadline it stops,
even if the mailbox itself has since earned a longer lease. A separately
authorized decision with a fresh operation ID is needed for later access.
Static recipients omit account/context arguments and use their existing static
lifecycle. Adoption of a static recipient into a lease invalidates an old
unleased overlay until it is explicitly reviewed again.

Grants and withdrawals are append-only SQLite audit records with stable operator
operation IDs, unique across both logs. Withdrawal requires the original
`--grant-operation-id` and exact recorded sender/recipient/conversation and
peer/native scope. It does not require active endpoints, an outgoing route,
current policy/account files, or the original credential generation to remain
active. `--expected-generation` on withdrawal checks the original recorded
generation. Reusing an ID for different arguments fails; retrying an old grant
cannot undo its withdrawal or extend its cutoff, and retrying an old withdrawal
cannot target a later independently approved grant. The overlay adds no owner, role,
conversation, credential or subscription. It preserves existing authentication
fingerprints and performs current decision checks on each route use, including
inside transaction-time staging and notification authorization. It keeps the
256-route/32-routes-per-conversation bounds and stops admitting grants at 8192
decision records. A separate primary/foreign-key constrained log reserves one
withdrawal slot per grant (at most 8192 additional records), so a saturated grant
log cannot strand access. A second new withdrawal ID for an already withdrawn
grant is rejected; retries use the recorded withdrawal ID. No history is deleted
and audit storage is bounded to at most 16384 records across both logs.

## Future Relay command (not executed)

Deploy and validate the reviewed patch through the approved deployment procedure
first. Code deployment/service restarts are separate from the approval to grant
this exact route. Obtain an action-time preview on the operator host by adding
`--dry-run` to the command below. Preview uses a read-only SQLite source and an
in-memory snapshot; policy, live leases and live grant decisions are untouched.
Check its current generation/deadline. `--expected-generation N` optionally
pins that observed generation for the actual command.

Run using the existing app/operator identity on the Babel host, with the reviewed
source importable at `/srv/agent-babel`. No SSH admission or wrapper allowlist
change is necessary; the existing collector wrapper remains bootstrap-only.

```sh
runuser -u agent-babel -- env PYTHONPATH=/srv/agent-babel \
  /srv/agent-babel/venv/bin/python -m babel return-route \
  --database-file /var/lib/agent-babel/bridge.sqlite3 \
  --policy-file /etc/agent-babel/agents.json \
  --accounts-file /etc/agent-babel/trusted-accounts.json \
  --action grant --operation-id ember-relay-return-20261012 \
  --sender bits255.dots.ada_20261002 \
  --recipient bits255.codex.auto_08d25f8de37f3154f71b7771de2b130c \
  --conversation report_auto_08d25f8de37f3154f71b7771de2b130c_ember \
  --peer mikkel@pop-os \
  --native-id 01a13177-7b11-77c0-9791-eec57c127ac1
```

The grant result states whether a decision was written (`changed`), the currently
effective route (`effective`), and the captured generation/deadline. An expired,
revoked, disabled, mismatched or static-conflicting session fails closed.
After applying only this authorized grant, refresh Ember's `list_contacts` and
verify one reply with the existing conversation and `reply_to`, then claim and
acknowledge it through Relay's own authenticated mailbox. This is mailbox
delivery verification; native wake still needs separate exact-session setup.

To withdraw this overlay, the future command is:

```sh
runuser -u agent-babel -- env PYTHONPATH=/srv/agent-babel \
  /srv/agent-babel/venv/bin/python -m babel return-route \
  --database-file /var/lib/agent-babel/bridge.sqlite3 \
  --action revoke --operation-id ember-relay-withdraw-20261012 \
  --grant-operation-id ember-relay-return-20261012 \
  --sender bits255.dots.ada_20261002 \
  --recipient bits255.codex.auto_08d25f8de37f3154f71b7771de2b130c \
  --conversation report_auto_08d25f8de37f3154f71b7771de2b130c_ember \
  --peer mikkel@pop-os \
  --native-id 01a13177-7b11-77c0-9791-eec57c127ac1
```

Withdrawal results state `withdrawn` and `changed`; `effective` is null because
withdrawal does not load current policy or claim that another independent grant
is absent. It writes no current policy or lifecycle changes. This does not remove
any independently configured static grant; those continue to use `policy ungrant`.
Use `--dry-run` to preview either action without live database writes.
General client support is not permission to apply additional routes.

## Bounded rollout and rollback

The additive migration creates two audit tables and one route index, with no
existing policy, credential, subscription, outbox, trigger or service-argument
changes. All three long-lived gateway/operator/wake-worker processes must load
the reviewed code before any overlay grant. The existing single gateway needs
an approved bounded restart or an already established HA cutover; uninterrupted
availability is not proved by the local tests.

Rollback targets the prior deployed release without any return-route overlay,
retaining the additive audit tables and all existing data. No destructive DB
restore is required. When access must remain withdrawn on a later redeployment,
append its exact grant's withdrawal first; it remains possible with saturated
grant audit, inactive endpoints, expired leases or unavailable policy/account
files. Do not roll back to the superseded intermediate candidate, which does not
understand withdrawal tombstones. Independently approved newer grants need their
own exact withdrawal IDs; do not replay or remove queued history to force rollback.
