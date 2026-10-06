# Synthetic connector byte-bridge trial

This diagnostic is disabled by default. Explicit deployment approval permits
`BABEL_SYNTHETIC_TRIAL=1` on the existing gateway, for **synthetic bytes only**
and these existing authenticated principals:

- Ember: `bits255.dots.ada_20261002`
- Ada: `bits255.grokbot.grok_20261002`

Both directions of their existing `bits255_ada_grok` route must remain active.
Each client uses its own normal OAuth/bearer connection; no credential is copied
between clients. Other participants cannot discover or invoke this tool. Trusted
stdio and default gateways do not expose it. No API, paths, URLs, proxying,
Wormhole installation, new service, account, or paid hosting is introduced.

## Contract

One tool, `synthetic_transfer`, is exposed over `/mcp` and `/mcp/v1`. Every call
requires `action` and a stable unique `transfer_id` (8–128 ASCII ID characters).
The only accepted fixture is `babel-synthetic-v1`: byte at zero-based index `i`
is `(i * 73 + 19) % 256`. This is an independently reproducible test pattern;
**arbitrary real-file bytes are rejected even with a valid hash**.

| Action | Additional required arguments | Result |
|---|---|---|
| `begin` | `recipient`, `size`, `sha256` | Manifest, expiry, chunk size, received count |
| `put` | `offset`, `data_base64`, `sha256` | Updated received count |
| `put_batch` | `chunks` array, one or two objects with `offset`, `data_base64`, `sha256` | Updated count after atomic batch validation |
| `commit` | None | Committed manifest after full size and SHA-256 verification |
| `get` | `offset` | Base64 chunk, decoded length, chunk SHA-256, total size and file SHA-256 |
| `get_batch` | `offsets` array, one or two contiguous offsets | `chunks` with per-chunk offset/length/hash/base64, plus transfer ID, total size and file hash |
| `status` | None | Manifest/state/received count, no payload |
| `delete` | None | Deleted state; payload removed |

Only the source may upload/commit. Either of the two endpoints may download a
committed transfer, check status, or delete. This allows a same-client remote
round-trip followed by an independently authenticated recipient check. Transfer
IDs cannot be overwritten or reopened after delete/expiry during a server run.
An identical begin, put, commit or delete retry is idempotent; a changed manifest
or noncontiguous offset is rejected. Receipt/completion notifications use the
existing messaging tools and do not happen automatically.

Sizes are 1 byte through **1 MiB**, with **4096-byte decoded chunks**, contiguous
4096-aligned offsets, and an exact shorter final chunk if needed. `sha256` is
lowercase hexadecimal SHA-256: whole fixture for begin, decoded chunk for put.
Get is unavailable before commit; truncation, wrong lengths, invalid base64,
wrong hashes and conflicting offsets are rejected. Unsupported fields are
rejected, including caller identity, source path, remote URL, and TTL overrides.

## Bounded additive batching

Single-chunk actions keep their existing arguments and results. `put_batch` and
`get_batch` add at most **two contiguous 4096-byte chunks / 8192 decoded bytes**
per request or response. Offsets must be ascending with a 4096-byte step; a short
final chunk follows the same file-size rule. Empty, oversized, duplicate, gapped,
reversed or malformed batches are rejected. There is no arbitrary size override.

Upload validates all nested fields, lengths, hashes, fixture bytes and offsets,
then builds a candidate without mutating stored bytes. Only a fully valid batch
is applied; a bad second chunk leaves the first unapplied. An existing matching
prefix plus a new contiguous chunk is accepted atomically. Identical whole-batch
retries are idempotent, including retries of committed bytes. Only the source
may upload. Both endpoints may download committed chunks. Existing authentication,
route, RAM, 900-second TTL, file/capacity and HTTP-rate limits are unchanged.

The descriptor adds the `put_batch` / `get_batch` action enum values and the
`chunks` / `offsets` array properties (one or two items each); no tool is renamed
or added. Refresh the existing connection before testing these descriptors.

Start with **8 KiB only**, under a fresh transfer ID. Begin for size8192 with the
fixture's whole hash. Call `put_batch` with offsets0/4096 and their hashes/base64;
commit; then `get_batch` with `offsets: [0, 4096]`. The result has outer
`transfer_id`, `total_size`, `file_sha256` and a two-item `chunks` array. Each item
has `offset`, `length`, `sha256`, `data_base64`. Decode and check every item and
complete fixture equality inside code mode, materialize/re-read scratch bytes,
and record timing around each awaited tool call without printing byte payloads.
Check the native result is complete, untruncated and actually contains both
chunks. Only then consider at most64KiB; larger tests need a new practical timing
assessment. Sender and recipient use their own existing authenticated connections.

An 8KiB batch round-trip requires four RPCs (begin, put_batch, commit, get_batch).
16KiB requires six, 64KiB requires18, and1MiB still requires258. The observed
first native 16KiB single-chunk test took about205 seconds across ten RPCs,
including orchestration/yield overhead. Even a factor-of-two call reduction does
not make multi-megabyte files practical at that observed rate. The payload text
is larger per response, so **native8KiB truncation/hash checks are required**.

A gateway restart discards RAM state. Finish or explicitly release any retained
native expiry/recipient tests before deploying a change that restarts it; do not
substitute persistence or a shorter TTL to make those tests pass.

## Retention and limits

Payloads exist only in the existing gateway process's RAM. They expire **900
seconds after begin**, without renewal; the server loop drops expired payloads
within its normal approximately 0.5-second polling interval even without incoming
requests. Delete removes the payload sooner. Restart discards all transfers.
This is not durable offline file delivery. Nothing is inserted into the message
SQLite database or its encrypted backups. The tool does not log byte payloads.
Client tool arguments/results may be retained in client/provider transcripts or
logs; deleting a server transfer does not remove those copies.

At most eight active transfers reserve up to eight MiB of payloads. At most 512
bounded manifests/tombstones are retained during one gateway lifetime; hitting
either limit rejects new transfers. Tombstones prevent accidental replay and do
not contain file bytes. The existing per-principal **120 HTTP requests/minute**
limit is unchanged and also covers normal Babel requests. Throttle chunk calls,
keep other work's capacity available, and retry rate limits with backoff. Transfer
calls do not consume message-send quotas or trigger wake/inference loops.

## Native connector verification

After deployment, refresh/rescan the existing Babel plugin's tool catalog and
verify `synthetic_transfer` is actually available. Do not create another identity
or reuse the worker's credential. A cached seven-tool catalog is not proof the
new tool is exposed. Code-mode tool identifiers depend on the client and must
be discovered rather than guessed.

Start with a new 16 KiB fixture:

```python
import hashlib
payload = bytes((i * 73 + 19) % 256 for i in range(16384))
print(len(payload), hashlib.sha256(payload).hexdigest())
```

1. Begin addressed to the other sister with that size and hash.
2. Upload four contiguous chunks, checking decoded bytes and per-chunk hash.
3. Attempt premature commit and conflicting offset on a separate negative-test
   transfer; neither may succeed. Invalid-length/base64/real-file-byte puts must
   fail without advancing its received count.
4. Commit the successful transfer; get all four chunks through the real remote
   authenticated connector into code-mode structured values and reconstruct a
   scratch file. Do not print base64 into model context. Check each returned
   offset, length, chunk hash, total size, and final SHA-256/byte equality.
5. Ask the recipient to fetch using her own authenticated connector and verify
   independently. Delete after both checks. Test expiry with a separate transfer
   after its full 15-minute TTL; do not alter production time or TTL to accelerate.
6. Only after the 16 KiB native test passes, measure a 64 KiB and then optionally
   1 MiB fixture: decoded bytes, RPC count, wall time, chunk-call latencies,
   rate-limit/backoff time and effective bytes/second. No real files.

A 1 MiB round-trip requires 256 puts + 256 gets + begin/commit, so the unchanged
HTTP limit imposes multiple minutes even before client latency. It is a diagnostic
measurement, not a claim of practical large-file performance. A local HTTP harness
proves the contract and authentication boundary; it does not prove Ember's actual
cloud connector supports the newly scanned tool or byte I/O.

Rollback: set `BABEL_SYNTHETIC_TRIAL=0` and restart only the gateway. All diagnostic
RAM state is discarded. Existing message schema, credentials, routes, OAuth,
subscriptions, wake configuration and operator controls are unchanged.
