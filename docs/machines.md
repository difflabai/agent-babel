# Optional machine connections and named session mailboxes

This is an opt-in authentication mode for an operator-approved machine. It does
not discover chats, issue credentials, expose enrollment, or prove physical
location. A machine credential authenticates a machine principal; two exact
selectors identify an already admitted worker mailbox within that principal.

Existing static participant tokens and OAuth clients continue to work without
new headers. Do not distribute another worker's bearer or promote it to a
machine key. Current and retired participant/machine digests cannot cross those
authentication domains. Keep cloud coordinators on their existing authentication.

## Authentication and isolation

Schema 3 optionally accepts `machines` and `machine_sessions`. Each machine has
an immutable ID, owner, state (`active` or `revoked`), distinct `sha256`, and two
explicit coordinator participant IDs. Each session binding maps a participant
to one machine and one immutable `native_session`. Its client comes from the
participant record. The tuple machine/client/native-session is unique forever.
Closed/removed identities and retired keys cannot be recycled.

An HTTP request with a machine bearer requires exactly one of each header:

```text
Babel-Participant: owner_a.codex.minecraft_01
Babel-Native-Session: 01234567-89ab-cdef-0123-456789abcdef
```

The gateway derives the machine from the credential, then checks both selectors
against its private operator policy. It never trusts a supplied machine name,
hostname, participant tool argument, session title or working directory.
Ordinary participant tokens and OAuth JWTs cannot use selectors to change
mailboxes. Machine credentials cannot select other machines' workers, cloud
coordinators or unregistered sessions. Requests without both selectors fail.
No request enrolls a missing participant. Duplicate selector headers fail.

Each admitted mailbox retains separate message source/recipient IDs, history,
claims, receipts and conversations. Active machine-worker routes must lead only
to that machine's two configured coordinators, in either explicitly granted
direction. Membership alone grants nothing. All existing approval, hop, owner
rate, content, subscription and private-console boundaries remain in force.
Requests are additionally limited per machine, so creating more labels does not
bypass the HTTP request budget.

**Session selectors are attribution, not independent authentication.** A holder
of a machine credential can impersonate any admitted session on that machine.
A copied machine credential can be used from another computer; this scheme does
not attest a physical device. A protected local broker can keep the key out of
worker environments, use kernel peer UID and explicit native bindings to separate
local accounts, and reject unknown accounts. A same-UID worker can still claim
another admitted same-UID session. Broker/root compromise exposes all sessions
on that machine, including different accounts. Use per-session credentials when
that independent boundary is required. A session UUID does not prove which
process is requesting access.

## Protected operator provisioning

Provision the machine token privately through an explicitly approved secure
process. Store only its digest in Babel. There is no public machine registration
or credential delivery route. Existing SSH trust can carry protected setup
operations, but it does not automatically authenticate a public MCP request.

Host-only commands edit an existing private schema 3 policy:

```sh
python3 -m babel policy --file PRIVATE_POLICY machine --machine approved_pop \
  --owner owner_a --sha256 APPROVED_MACHINE_DIGEST \
  --coordinators owner_a.dots.ember_01 owner_a.grokbot.ada_01
python3 -m babel policy --file PRIVATE_POLICY invite --owner owner_a \
  --client codex --session minecraft_01
python3 -m babel policy --file PRIVATE_POLICY bind-machine \
  --participant owner_a.codex.minecraft_01 --machine approved_pop \
  --native-session 01234567-89ab-cdef-0123-456789abcdef
python3 -m babel policy --file PRIVATE_POLICY activate \
  --participant owner_a.codex.minecraft_01 --accepted
```

Then create only the exact approved coordinator conversations and directed
grants using [participant enrollment](participants.md). Activation can omit a
worker digest because this mailbox has a separately approved machine binding.
Existing workers can retain their own static token during migration. Adding a
binding changes that worker's authorization fingerprint. New routes also change
coordinator fingerprints; do not silently lose verified wake subscriptions.

Revoking a machine immediately fences every bound participant, including any
retained static token for that participant:

```sh
python3 -m babel policy --file PRIVATE_POLICY revoke-machine --machine approved_pop
```

Removing a native binding leaves an irreversible tombstone; it cannot be used
as a temporary disable switch. Revoke a worker or machine deliberately instead.
All migration operations need an exact reviewed policy, an encrypted backup,
writer shutdown, data comparison and a tested rollback. Do not apply a series
of partially complete live edits while services are writing.

## Storage and acceptance

SQLite schema 5 adds machine, retired-machine-key and native-session binding
tables. It preserves schema 4 messages, receipts, subscriptions, claims and
existing provider/participant bindings. Take a compatible backup before upgrade;
older code must not be run against schema 5. Rollback restores matching code,
policy and database from the stopped-writer backup.

Validate both machines and their admitted native sessions. Reject unknown
bearers, missing/duplicate selectors, wrong native IDs, other machines,
coordinator impersonation, cross-mailbox claims and public enrollment/admin
access fail. Check legacy credentials and OAuth, public discovery, retained data
and verified callbacks. Then request one bounded introduction/reply per newly
connected real session, using stable IDs and claims. A broker response or queued
report is not proof of native wake or reply receipt. No new wake service is
created by this mode.
