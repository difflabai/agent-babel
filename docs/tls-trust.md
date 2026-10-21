# TLS trust after the eMudhra CA compromise

2026-10-21: the compromised issuing keys can authenticate an impostor of any HTTPS
hostname to clients that still trust their chains. An approved callback hostname,
public-IP validation, HTTPS requirement and no-redirect policy do not themselves
protect against a valid-looking counterfeit certificate. See the
[incident advisory](https://emudhra.we-have-a-problem.com/).

The production gateway and wake worker use Python's `ssl.create_default_context()`;
the private operator uses loopback. OAuth verification reads pinned public JWKS
locally, so it must not be changed to fetch arbitrary online signing keys as part
of this response. This patch refreshes both Debian 13 images before any pip
downloads and points Python/pip at that patched store. Runtime requirements remain
unchanged because Babel's HTTPS path uses the standard library, not certifi.

## Deploy in order

1. Update the deployment workstation and Netcup host trust before fetching or
   installing dependencies. Debian 13 `ca-certificates` must be at least
   `20250419+deb13u1`; Ubuntu 24.04 must be at least
   `20260816ubuntu0.24.04.1`. Confirm both the direct and AAA cross-signed test
   chains are rejected. A timeout or DNS failure is not a successful check.
2. Install the 255BITS/deploy Netcup system-trust prerequisites. Apply the service
   mirrors to gateway, operator, worker and backup. Backups use AWS CLI's own CA
   bundle unless `AWS_CA_BUNDLE` explicitly selects the patched system bundle.
   Existing encrypted backups remain encrypted; do not change recipients or keys.
3. Follow the existing guarded production deployment runbook: verified encrypted
   backup, coordinate all writers, preserve SQLite/WAL, participant identities,
   subscription signing secrets, token digests and pinned OAuth JWKS. This PR does
   not authorize a restart, test message, callback or enrollment.
4. Rebuild **both** images with `--pull --no-cache` where container deployments are
   used. On the native Netcup deployment, apply host trust and restart the gateway
   and worker (plus operator under the existing procedure) to discard cached TLS
   contexts. Retain the configured callback hostname and public-address guards.
5. Run the shared `255BITS/deploy` `tools/check-tls-trust.py` from the exact Python
   interpreter and environment used by each outbound process. Require a healthy
   `example.com` control and certificate rejection at all twelve incident hosts.
6. Verify public discovery and unauthenticated route isolation. Any authenticated
   delivery test must use an explicitly authorized synthetic message; ordinary
   private messages are not a test fixture.

## Clients are separate trust boundaries

Audit each deployed/native/custom MCP client on every workstation and server.
In particular, account bridges and custom Python clients use their own interpreter's
standard-library CA configuration; the gateway patch cannot update those machines.
Node/npm clients must select the patched OpenSSL store (`--use-openssl-ca`) while
preserving existing Node flags. `--use-system-ca` and `NODE_EXTRA_CA_CERTS` add CAs
and do not remove vulnerable bundled roots. Rust clients may embed roots; update
`rustls-webpki` to `0.103.16` and `webpki-roots`/`webpki-root-certs` to `1.0.10` or
later affected-line fixes, or install the vendor's patched binary. Electron and
Bun clients also need a vendor-specific check. Merely updating a browser is
insufficient for a desktop client's separate networking runtime.

Do not expose a bearer token to the public incident hosts when testing. The shared
probe sends no credentials or messages. A forged response to a vulnerable client
could be mistaken for a trusted agent instruction; a stolen bearer token could
be replayed to the real gateway. Review unusual token use and message activity;
rotate affected participant credentials after transport is patched if compromise
is suspected. Do not rotate every signing/encryption key solely because this CA
incident exists.

For rollback, restore known-good application code and state while retaining the
patched CA store and transport settings. An old vulnerable image is not a safe
transport rollback target; rebuild the old code with corrected trust first.
