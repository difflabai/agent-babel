# Ada OAuth deployment path

Recommended path: **Auth0 Auth for MCP**, reusing an operator-approved tenant. OpenAI's [authentication guide](https://developers.openai.com/plugins/build/auth) supports CIMD, DCR and predefined PKCE clients, requires resource metadata and token validation, and notes that ChatGPT cannot present custom API keys. [Auth0's MCP documentation](https://auth0.com/ai/docs/mcp/overview) describes OAuth 2.1 discovery, resource-scoped tokens and client registration.

This repository implements Babel as the OAuth **resource server**, with public resource metadata, issuer/audience/scope/time/signature checks and explicit subject/client-to-agent binding. Auth0 owns login, authorization code/PKCE, refresh, registration and consent. No Auth0 account, plan, application, grant or key has been created. The operator must approve their tenant use and any plan/terms requirements before configuration. If there is no approved tenant, that provider choice remains a user decision; nothing enrolls them automatically.

A self-hosted [Keycloak provider](https://www.keycloak.org/securing-apps/oidc-layers) is an alternative with OAuth 2.1 client profiles, but adds identity-server operations and needs a separately verified resource-indicator/client mapping. It is not installed or silently substituted for the recommended Auth0 path.

## Operator setup

1. Follow the official [OpenAI/Auth0 scaffold setup](https://github.com/openai/openai-mcpkit/blob/main/python-authenticated-mcp-server-scaffold/README.md#2-configure-auth0-authentication) for Auth for MCP. Create a dedicated API identifier equal to `https://YOUR_DOMAIN/mcp`, RS256 signing, permission `babel`, and an access-token lifetime of at most 900 seconds. Choose the Auth0 JWT access-token profile (not encrypted/JWE). Prefer a dedicated tenant/API over changing an unrelated tenant default audience.
2. Enable the provider's MCP resource-parameter compatibility and OAuth discovery; it must advertise S256 and issue the exact configured resource audience. Confirm the actual metadata, rather than fabricating a discovery response in Babel.
3. Register/import the exact ChatGPT CIMD URL shown on your MCP/plugin management page, or use its supported predefined-client flow. Set user-delegated API access for **that application only** and scope `babel`; avoid a default grant to all third-party apps. Configure the exact redirect URI shown there. Do not guess callback IDs.
4. Select the one provider user authorized to operate Ada. Obtain its stable `sub` and the registered client's actual `azp`/client ID from provider administration. Babel grants no role based on email, display name, a client-supplied header or an unsigned token. Different users cannot inherit this binding.
5. Copy `deploy/agents.oauth.example.json` into ignored `secrets/agents.json`; replace issuer/resource/subject/client placeholders and the separate Grok static-token digest. Ada needs no static service token. The subject/client binding is a deliberate authorization choice, not a default.
6. Obtain the provider's **public** signing JWKS from the verified issuer's discovery `jwks_uri` using your approved administrative workflow. Save it as `secrets/provider-jwks.json`; do not insert private keys. Babel accepts up to eight RS256 RSA public signing keys of at least 2048 bits. It never fetches a key URL supplied by a token. Inspect/replace the file and recreate gateway/worker when the provider rotates keys. Public key files still stay outside Git for deployment hygiene.
7. Build/start the OAuth and wake overlays:
   ```sh
   docker compose -f compose.yaml -f compose.wake.yaml -f compose.oauth.yaml config --quiet
   docker compose -f compose.yaml -f compose.wake.yaml -f compose.oauth.yaml build
   docker compose -f compose.yaml -f compose.wake.yaml -f compose.oauth.yaml up -d
   ```
   Prepare `secrets/wake.json` as described in the README first. File permissions must allow container UID 10001 to read mounted configuration.
8. In Work cloud/dot plugin setup, use `https://YOUR_DOMAIN/mcp`, select OAuth, sign in through the provider, and consent to `babel`. Confirm the real issued access token has issuer/audience, `sub`, `azp`, `scope`, `iat` and `exp`. Token lifespan must be no more than 15 minutes. An ID token or another application's token must fail.
9. Authorize a recipient `ada` subscription to `babel.message.approved`. Approve the actual client callback host in `wake.json`; the client supplies its callback URL/signing secret. Verify callback challenge, approve a synthetic Grok-to-Ada message, confirm event arrival, then claim/acknowledge it. Repeat Ada-to-Grok and prove a duplicate wake cannot claim an acknowledged message.

## Served metadata and enforcement

`GET https://YOUR_DOMAIN/.well-known/oauth-protected-resource` and its `/mcp` suffix return public standards metadata only. They expose no messages, user profile, UI or credentials. Unauthenticated MCP requests return 401 with a `WWW-Authenticate` resource metadata challenge. Authenticated tool descriptions include the OAuth security scheme and required scope.

In a static-only deployment the two discovery URLs are also public, describing the resource and header-based bearer transport. They omit authorization servers and OAuth scopes until a real provider is configured. Public metadata alone does not enable ChatGPT OAuth sign-in; complete the provider and principal setup above first.

To discover a real configured provider before enrolling its users, an operator may use an explicit empty `oauth.principals` object with the verified issuer and pinned public JWKS. All OAuth users are denied until exact bindings are added; existing static credentials continue to work. This supports obtaining the actual native client metadata and user identity during setup without placeholders or automatic enrollment. It does not complete OAuth acceptance.

JWT algorithms are fixed to RS256; `kid` only selects a pinned key. Issuer and resource audience must match exactly. Expiration/not-before/issued-at are validated. `babel` scope and the exact configured subject/client pair are required. Unknown signing keys, algorithm substitution, overlong lifetime, other accounts/clients and malformed tokens fail closed. Ingress role binding and recipient claims apply identically to OAuth and static credentials.

Offline signature verification cannot instantly see a provider-side logout/revocation. Short access-token lifetimes bound that window. To revoke bridge access immediately, remove its explicit principal binding from `agents.json` and recreate the gateway/worker. Worker authorization fingerprints invalidate old subscriptions when bindings change; fresh access-token issuance alone does not change subscription identity.

## Test evidence versus setup

Signed synthetic JWT tests exercise signature, issuer, audience, scope, expiry, subject, client, key selection and public metadata challenges. Docker validation proves the resource-server dependencies build. The test signing keys exist only in memory and are not production credentials. A real provider authorization-code/PKCE exchange, grant, callback subscription and both native clients are **deployment acceptance tests**, not a result claimed by mocked tests.

Use the same three Compose files for ongoing operations. Keep provider/client secrets in provider-managed storage; Babel does not need an OAuth client secret or an OpenAI API key.

For invited owners or multiple client/session identities, use [schema 3 participants](participants.md) and its OAuth template. Bind exact provider principals to instance IDs; duplicate subject/client pairs cannot select multiple simultaneous dots. Ordinary legacy role configuration remains supported.
