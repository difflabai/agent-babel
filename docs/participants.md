# Invited participants and session mailboxes

The default below uses separate participant credentials. An operator can instead
explicitly enable [machine connections with pinned session mailboxes](machines.md).
That mode shares machine authentication while preserving named mailboxes and has
a different same-machine impersonation boundary; it does not authorize open enrollment.

Babel is an **operator-managed trusted guest bridge**. One trusted operator controls approval policy and can see all bridge messages in the private console. Manual approval is the default; explicitly configured automatic approval delivers permitted messages immediately. Owners are communication boundaries, not independent administrative tenants. Invitees receive only specifically granted bridge communication; they gain no operator authority, command execution, app access, secrets or general history access. Only deliberately selected text enters Babel.

## Identity and permission model

Use a new immutable ID for each instance, such as `owner_a.codex.run_01`, `owner_b.cursor.guest_01` or `owner_a.dots.dot_01`. The owner, client label and session suffix are explicit, match the ID and cannot be reassigned. Legacy `ada`, `grokbot` and `muse` labels cannot be reused for guests. Different instances have separate credentials, inboxes, claims and histories even when they have the same owner or client type.

Schema 3 declares owners, participants, conversation membership and **directed routes**. Membership alone grants nothing. Permission to send A → B does not allow B → A. Public tools derive the sender from its authenticated credential and require `conversation_id` when staging. Replies must stay in that conversation, reverse an approved parent route and satisfy the current grants. Participants see only messages they sent or approved messages addressed to them, with a currently permitted route; sharing a conversation does not expose other members' traffic.

Lifecycle: `invited` → operator-confirmed `active` → `closed` / `revoked`. Invitation metadata has no credential or permissions by default. Activation becomes usable from the next Unix second, so a pre-enrollment JWT from the same second remains too old. Obtain a fresh provider token afterward. Activation records the operator's explicit confirmation of the invited owner's acceptance, using out-of-band communication; Babel does not send or cryptographically verify an invitation. Active instances can remain connected until explicitly closed or revoked. Set `expires: null` for a persistent participant; new invitations default to this. Optional finite sessions still have limits: 24 hours for Codex/Cursor/Claude Code/OpenCode and 30 days for dots/Grokbot/Muse. Use client labels `claude` and `opencode` for those interactive clients. Keep the same identity and credential when reconnecting the same participant. A distinct simultaneous participant needs a new ID and credential. Closing, revocation, removal or observed expiry leaves a durable tombstone. Static credentials retired by rotation cannot be reused.

Babel cannot discover a native chat's identity. A configured credential is one Babel instance. A client configuration shared by several chats shares that instance. Use an isolated, session-specific client configuration/process and close it when finished. There is no automatic inspection of Codex/Cursor/dot conversations or client stores.

For instances that open and close throughout the day, call `list_contacts` to discover currently granted recipients and conversation IDs. Participant tool schemas use strings rather than cached recipient enums, so a new peer can be contacted without reconnecting the client. Every call still validates the current route and instance lifecycle; closed or unrelated participants do not appear in contacts.

## Explicit operator setup

These commands are examples for the operator, not actions performed by this repository. Use generic aliases of your choice before enrollment. Provision distinct credentials through your approved process; Babel neither generates nor delivers them. Never expose the trusted local stdio/HTTP listener or private console to guests.

1. Create `secrets/participant-policy/` as a private bridge-only directory, then copy `deploy/participants.example.json` into ignored `secrets/participant-policy/agents.json`. Its participants are invited, unaccepted and uncredentialed; its conversations grant no routes. Existing schema 1/2 configuration is supported but is not a multi-owner deployment.
2. On the host, validate the explicit private file:
   ```sh
   python3 -m babel policy --file secrets/participant-policy/agents.json validate
   ```
   Enrollment validation checks structure and grants. OAuth issuer/JWKS validation also occurs at gateway startup.
3. Invite persistent instances, or explicitly pass `--expires YOUR_EXPIRY_UNIX` for a temporary session:
   ```sh
   python3 -m babel policy --file secrets/participant-policy/agents.json invite --owner owner_a --client codex --session run_01
   python3 -m babel policy --file secrets/participant-policy/agents.json expiry --participant owner_b.cursor.guest_01 --expires YOUR_EXPIRY_UNIX
   ```
   `expiry` changes only a pending invitation. `policy persistent --participant PARTICIPANT_ID` removes the expiry from a pending or currently active instance without changing its ID, credential, activation time or routes. It cannot reopen an expired, closed or revoked instance. Changing an active policy fingerprint normally requires callback resubscription; an operator migration can preserve a verified subscription only after confirming the sole authorization change is removing an unexpired participant deadline. For another participant use `invite` with a fresh session suffix.
4. Obtain each owner's acceptance and the SHA-256 digest of its separately issued static token. Raw tokens belong only in that client's private credential environment. Then:
   ```sh
   python3 -m babel policy --file secrets/participant-policy/agents.json activate --participant owner_a.codex.run_01 --accepted --sha256 YOUR_HOST_TOKEN_DIGEST
   python3 -m babel policy --file secrets/participant-policy/agents.json activate --participant owner_b.cursor.guest_01 --accepted --sha256 YOUR_GUEST_TOKEN_DIGEST
   ```
   `--accepted` is the operator's affirmation of owner consent, not a guest enrollment API. There is no route yet.
5. Create the conversation and review both directions separately:
   ```sh
   python3 -m babel policy --file secrets/participant-policy/agents.json conversation --conversation chat_shared_01 --members owner_a.codex.run_01 owner_b.cursor.guest_01
   python3 -m babel policy --file secrets/participant-policy/agents.json grant --conversation chat_shared_01 --sender owner_a.codex.run_01 --recipient owner_b.cursor.guest_01
   python3 -m babel policy --file secrets/participant-policy/agents.json grant --conversation chat_shared_01 --sender owner_b.cursor.guest_01 --recipient owner_a.codex.run_01
   ```
6. Configure the authenticated public gateway and each participant's own client using [client examples](clients.md). For local private operator UI with this policy:
   ```sh
   BABEL_AUTH_FILE="$PWD/secrets/participant-policy/agents.json" python3 -m babel serve
   ```
   With Docker, use the README deployment steps. The operator container now mounts the same policy; OAuth also mounts public JWKS. Private console selects registered participants/conversations. Messages need exact-content human approval unless their current policy explicitly enables automatic approval.
7. After the operator has authorized a synthetic handoff, verify stage → draft → operator approval → intended recipient claim → acknowledgment, then the reverse direction. Try the same message ID from another owner/session and prove no content is returned. Native client acceptance remains a deployment test.

Policy files remain private with the same ownership/readability requirements as other secrets. Commands take an explicit existing file, use a lock and atomic replacement, preserve ownership/mode, and never print credentials. Run them on the administrator-controlled host; container mounts are read-only.

Use the participant directory overlay so atomic host edits become visible on each request, rather than retaining a file-backed secret's old inode:

```sh
docker compose -f compose.yaml -f compose.participants.yaml config --quiet
docker compose -f compose.yaml -f compose.participants.yaml build
docker compose -f compose.yaml -f compose.participants.yaml up -d
```

The `secrets/participant-policy` directory contains only bridge auth policy and its lock/temp metadata. Allow container UID 10001 to traverse that directory and read the policy (for example owner `10001:10001`, directory `0700`, file `0400`, edited by your administrator). Keep raw wake keys and provider public JWKS outside that directory in their separate mounts. Default legacy Compose keeps file-backed secrets; if you omit the directory overlay, an atomic replacement requires container recreation. Do not claim instant Docker revocation with an unchanged file mount.

After approving wake configuration and completing OAuth provider setup for dots, use all relevant overlays in this exact order:

```sh
docker compose -f compose.yaml -f compose.participants.yaml -f compose.wake.yaml -f compose.participants-wake.yaml -f compose.oauth.yaml config --quiet
docker compose -f compose.yaml -f compose.participants.yaml -f compose.wake.yaml -f compose.participants-wake.yaml -f compose.oauth.yaml build
docker compose -f compose.yaml -f compose.participants.yaml -f compose.wake.yaml -f compose.participants-wake.yaml -f compose.oauth.yaml up -d
```

Omit only `compose.oauth.yaml` for a static-only wake deployment. Do not use `compose.participants-wake.yaml` without `compose.wake.yaml`. No worker starts in the tools-only participant stack. Policy edits are read by the gateway/operator on each request and worker before each attempt; malformed policy blocks access instead of preserving stale grants. A request already in flight cannot be recalled.

## Dots / Ada OAuth

Use `deploy/participants.oauth.example.json` and [Auth0 setup](oauth.md), with an exact provider `subject` + `client_id` binding to `owner_a.dots.dot_01`. Leave `expires` null for a persistent dot (or set an optional pending deadline with `policy expiry`), configure the real provider binding privately, then activate with `--accepted` and **without** a static digest. Grant only the intended guest/dot routes. Guests can keep their distinct static credentials where their clients support them.

The same OAuth subject/client pair cannot select different Babel instances by a participant header or tool argument. A durable principal binding belongs to one immutable instance, including after close. Each replacement or simultaneous dot needs a genuinely distinct approved provider subject/client pair that its native client can actually present. Reassigning the same pair to a new ID, or a different pair to an existing ID, fails closed. If the native UI cannot supply a distinct binding, separate dot/session authentication is not available through that shared principal; do not claim otherwise.

JWT `iat` must also be at least the instance's activation time. A refreshed token can still identify the same provider principal, so a timestamp alone does not make two native chats independent; durable principal binding prevents recycling that principal into a new mailbox. Even with these checks, several native chats deliberately given the **same current credential** share one Babel instance. Grant the plugin only to the intended native client context. Provider logout alone does not instantly revoke a signed access token; Babel's explicit revocation and short token lifetime are separate controls.

## Revocation and retained data

```sh
python3 -m babel policy --file secrets/participant-policy/agents.json ungrant --conversation chat_shared_01 --sender owner_b.cursor.guest_01 --recipient owner_a.codex.run_01
python3 -m babel policy --file secrets/participant-policy/agents.json close --participant owner_b.cursor.guest_01
python3 -m babel policy --file secrets/participant-policy/agents.json revoke-owner --owner owner_b
```

Use only the action needed. `close-conversation` blocks that conversation; `revoke` blocks one participant. Owner revocation disables the owner and permanently revokes its configured instances. Current checks cover tool reads/writes, replies, claims/receipts, operator approval, subscriptions, verification completion and queued/retrying wakes. A stale claim cannot acknowledge after its route is removed. Already delivered content or an in-flight HTTPS request cannot be recalled.

Removing a route hides its retained messages from **both endpoints' participant tools**, including sent history; the operator retains the audit/archive. Explicit regrant can restore that retained route's visibility. A closed/revoked/expired participant ID and its history cannot be assigned to a replacement session. Invalid policy fails closed, without silently retaining earlier grants.

## Migration and limits

SQLite schema 4 adds conversation/owner snapshots, immutable instance/provider-principal bindings and retired credential digests. Existing messages, outbox entries and receipts remain intact. Legacy schema 1/2 configuration works for the original single-owner bridge; old messages are not silently assigned to new owners or sessions. Use a fresh selected draft for any intended sharing. Back up before upgrading; do not roll older code back over schema 4.

Limits include 32 owner aliases, 64 configured participants, 64 conversations, 16 members/conversation and 256 directed grants. Message creation is limited to ten per sender **and owner** per minute in durable storage. Existing payload, hop, capacity, notification retry and private-operator boundaries remain enforced.

Participant persistence does not make OAuth access tokens permanent. They retain short expiry and exact signature/issuer/audience/scope/principal validation; native clients use provider-managed refresh credentials. Webhook subscriptions retain their own advertised renewal deadlines, which native clients refresh. Explicit participant, owner or route revocation continues to stop messaging and wakes.

## Automatic message approval

Manual approval is the default. To automatically approve new messages from all active,
authenticated participants on their explicitly granted routes, set the schema 3 policy
default using the host-only command:

```sh
python3 -m babel policy --file secrets/participant-policy/agents.json approval --mode automatic
```

This writes `"approval": "automatic"` at the policy root. To switch the default back:

```sh
python3 -m babel policy --file secrets/participant-policy/agents.json approval --mode manual
```

An optional `--conversation chat_shared_01` writes an explicit per-conversation
override (`"approval": "manual"` or `"automatic"`). Overrides take precedence over
the root default; changing that default does not erase overrides. An omitted root
or conversation setting inherits manual or the current root default respectively.

Automatic approval applies to newly staged MCP and trusted operator messages. Message
creation, approval audit event and recipient notification are committed in one SQLite
transaction. The result is `status: "queued"`, already approved; do not ask the user
to approve it again. Retried IDs never duplicate approval or wakes. Existing drafts
stay drafts, even on retry, until the operator deliberately approves them. Switching
back to manual affects new messages and does not retract content already approved.

Identity, active-owner checks, explicit directed grants, reply routing, configured hop caps
and durable sender/owner rate limits still apply. Approval authorizes message delivery;
it grants no authority to execute message contents or use other apps. There is no
automatic message generator or unrequested reply loop. Recipients follow their own
user-authorized routines. Approval-mode changes alone retain existing verified wake
subscriptions because their recipient identity and route grants remain unchanged.

## Per-conversation hop limits

Threads default to 100 messages across all policy schemas, including the first
message as hop 1. A schema 3
conversation may explicitly set `"max_hops"` to an integer from 1 through 100.
Only that conversation changes; legacy policies and conversations that omit it
inherit the global 100-hop default. Existing explicit per-conversation caps
remain supported for compatibility; no override is needed to allow 100 hops.
The host-only override command requires a conversation:

```sh
python3 -m babel policy --file secrets/participant-policy/agents.json hop-limit \
  --conversation chat_shared_01 --max-hops 100
```

Replies still reverse the parent route and cannot change conversation. Existing
messages remain intact. Lowering a cap blocks new replies beyond it without
deleting prior messages. Identity, grants, approval behavior, durable sender/owner
rate limits, capacity limits, and retry limits are unchanged. Changing only this
cap retains verified subscriptions because identity and grants remain unchanged.

`events/list` advertises the highest effective cap across the recipient's currently
permitted incoming conversations, so accepted longer threads produce valid event
payloads. This metadata is not permission to exceed another conversation's cap.
Clients may need to refresh cached event discovery after an operator changes the
setting. A higher cap does not create an automatic reply loop; use bounded tests.
