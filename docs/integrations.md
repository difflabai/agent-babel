# Integration boundaries

Research reviewed against official public documentation on 2026-10-02. No installed application state, transcripts, credentials or local databases were inspected for this cloud build.

- [MCP 2 protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning) and [discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover): Babel implements a stateless 2026-07-28 public interface separately from the legacy initialize-based tools endpoint.
- [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events): Work cloud chats and dots can use webhook event subscriptions. Babel implements the documented subset, with recipient filters, persistent finite subscriptions, signed callback verification and a notification outbox. No live registration has been performed.
- [Draft event contract](https://github.com/modelcontextprotocol/experimental-ext-triggers-events/blob/main/docs/design-sketch-proposal.md) and [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md): the implementation uses HMAC-SHA256 over ID, timestamp and exact body bytes, separate stable subscription IDs and bounded key rotation. This draft subset is explicitly distinct from core task execution.
- [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli): explicit Bearer credentials from environment-backed configuration are documented. Local tools and event-driven Work cloud behavior are separate capabilities.
- [OpenAI plugin authentication](https://developers.openai.com/plugins/build/auth): ChatGPT does not support custom API keys. Babel implements a resource server for provider-issued OAuth tokens with pinned RS256 public keys and explicit principal bindings; [Auth0 setup](oauth.md) handles provider registration/PKCE/consent. No live account or grant is created.
- [Grok Remote HTTPS MCP](https://docs.x.ai/grok-bot/team-bots): remote servers and configured credentials are documented, but the exact header mapping/client version must be validated in the intended account. No laptop app gateway is assumed.
- Grok's routine wake wire contract was supplied by the user, without credentials. It is implemented and mocked: Bearer JSON POST and HTTP 200 acceptance. It is not labeled independently verified official API documentation.
- [A2A specification](https://a2a-protocol.org/latest/specification/): a mailbox cannot stand in for task lifecycle, agent-card discovery or artifact execution. Muse/A2A adapters are extension work.
- [Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy): the deployed public ingress forwards authenticated MCP routes and public standards resource metadata, with explicit trusted proxy headers.

No third-party MCP mods are installed or bundled. Wider transcript/file/shell adapters are outside this bridge's scope.
