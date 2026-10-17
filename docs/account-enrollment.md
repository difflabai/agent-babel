# Automatic enrollment on an approved account

Native lifecycle hooks already prepare a private mailbox credential and bounded
schema-2 event metadata. Preparation alone does not authenticate that mailbox:
the existing private backend must accept its credential digest. This account
transport closes that gap without a registration command for each new session.

The transport is disabled unless the owning approved UNIX account explicitly
enables it once. The account must already have its trusted account configuration,
native client integration, and existing pinned SSH operator access. The public
client package does not install keys, create an account, change backend grants,
or expose an enrollment endpoint.

After reviewing and installing the client package, the account owner can create
the owned private file
`~/.config/255bits/agent-babel/account-enrollment-transport.json` with mode `0600`:

```json
{"schema_version":1,"enabled":true,"transport":"pinned-ssh-operator"}
```

The account directory must also be owned and private. The integration validates
the executing UID's real account name and machine hostname against the existing
approved peer in `trusted-account.json`. It accepts no peer, destination, key,
command, credential, or account path from a model or lifecycle event. An absent,
disabled, malformed, foreign, or noncanonical configuration cannot start it.

New native lifecycle events schedule one shared, bounded background worker.
Existing native receiver/plugin polls can retry delivery of retained metadata
after a connection failure. These calls do not create events, renew a lease,
resume a dormant session, or start inference. The worker uses the already
configured SSH operator connection with batch public-key authentication and
strict host-key checking. No additional systemd service or timer is installed.
Native hooks do not wait for the network.

Set `enabled` to `false` to stop new submissions. The bounded worker rechecks
that owner setting before each request. Local counts and retry timing live in
`account-enrollment/status.json` under the account configuration directory;
the accompanying ledger retains accepted-event proofs and retry state. These
files contain metadata, and their counts do not prove a model wake or receipt.

The worker reads only owned, bounded lifecycle metadata beneath this account's
`automatic-instances` directory. It sends existing native IDs, event IDs,
credential digests, and observation times to the existing restricted private
operator command. It never reads or transfers token files, prompts, transcripts,
provider settings, or private report details. Server account/client allowlists,
capacity, revocation, credential rotation, and expiry remain authoritative.

A metadata receipt is written only after a valid response for the expected
automatic participant and conversation. A lost response retains the exact event
for an idempotent retry. Stale evidence cannot become fresh activity. One failed
session cannot indefinitely block newer eligible sessions. Existing participant
migrations retain their separate reviewed binding process; this transport does
not guess legacy identities or conversations.

Enabling this transport does not enable a client's missing native wake API.
Claude's channel confirmation and Grok's patched-runtime requirement still
apply. Verify a genuinely new session's authenticated contact lookup, then a
real coordinator reply that causes inference in that same idle session and is
claimed and acknowledged by its worker. A local event, accepted enrollment,
queued notification, or successful SSH command alone is not that proof.
