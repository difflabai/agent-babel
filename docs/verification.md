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
