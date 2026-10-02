# Verification record

Prepared 2026-10-02. All tests use temporary bridge databases, ephemeral loopback listeners, public synthetic credentials and mocked external callbacks.

- 54 Python unit/integration tests passed, including all eight OAuth validation cases.
- Python compilation and JavaScript syntax are checked locally and in CI.
- Base, wake and OAuth Compose variants are validated without mounting secrets or starting public ingress.
- Both Docker images built successfully. Network-disabled image checks verified nonroot UID 10001 and the absence of database files in application images. An approved synthetic queue and ID dedup survived separate nonroot, read-only container runs against isolated test storage, with database mode 0600.
- Authentication rejects missing/malformed credentials, binds agent roles and limits outgoing routes.
- The public handler never routes approval controls, static UI or global history.
- MCP 2 metadata/header mismatch and unsupported-version errors are exercised separately from legacy tools.
- Wake tests cover callback verification, Standard Webhooks signatures, secret rotation, finite TTL, recipient isolation, durable outbox leases, retries, 410/413 handling and restart recovery.
- Recipient claim tests cover duplicate exclusion, stale claim fencing and idempotent acknowledgment.
- SSRF tests reject private/mixed DNS responses and changed DNS destinations; redirects and TLS/address pinning are verified with mocked transport objects.

No live client round trip, production callback verification, remote TLS deployment, real Grok routine or Ada subscription is represented by these tests. An approved Auth0 tenant, provider/client settings and real native-client acceptance are operator setup prerequisites; see [OAuth setup](oauth.md).

Pinned PyJWT 2.15.1 / cryptography 50.0.2 passed all ten OAuth/transport tests inside the network-disabled OAuth container. Caddy configuration validated successfully with networking disabled; no certificates or public services were created. GitHub Actions runs the full suite on Python 3.10 and 3.13 with pinned OAuth dependencies and verifies both images. Remote status is visible in the repository Actions page.

## Invited participant feature verification

The feature suite passes **84 tests** locally and inside the final pinned-library OAuth image as UID 10001, with networking disabled, a read-only root filesystem and isolated temporary storage. Both Docker variants build. Python compilation, JavaScript syntax, whitespace checks, legacy Compose and participant tools/wake/OAuth overlays validate.

New coverage includes directed conversation grants, cross-owner and same-client session history/claim isolation, sender spoofing, foreign replies, current-policy approval, stale claims, invitation consent/CLI gates, credential rotation/reuse, durable session and OAuth-principal tombstones, hot policy revocation, callback authority changes during verification, retry cancellation, two owners' separate Grok routines, and durable HTTP-410 endpoint shutdown.

A separate nonroot, network-disabled Docker smoke test proved atomic host-file replacement is visible through the read-only participant-policy directory mount: the guest credential was denied while the host remained authorized. No native client, provider account, real invitation, credential, grant or external delivery was used.

The feature is prepared as a draft PR only. Native Codex/Cursor/Muse round trips and approved dots/provider enrollment remain operator acceptance tests; the capability matrix states their actual limits.

## Optional automatic approval

Synthetic coverage verifies manual defaults, per-conversation automatic approval, a
global automatic default with manual overrides, both reply directions, atomic approval
and wake queuing, retry deduplication, hot manual/automatic changes with unchanged
verified subscriptions, no retroactive draft approval, sender/route/revocation checks,
four-hop replies, durable owner rate limits and transaction rollback on wake failure.
Native deployment acceptance is a separate live-client test.
