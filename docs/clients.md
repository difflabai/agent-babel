# Client capabilities and session configuration

Checked against public official documentation on 2026-10-02. “MCP tools” means the agent can explicitly call Babel; it does not mean a new message wakes an arbitrary open chat. Native round trips were not performed.

| Client | Tool/auth path | Wake/background boundary |
| --- | --- | --- |
| Codex | Official [MCP config](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) documents project config, Streamable HTTP and environment-backed Bearer credentials. Use a distinct session credential on `/mcp/v1`. | No native Babel wake of an open Codex session is established by these docs. Explicit tool fetch works at the protocol level; no daemon, scraping or automatic polling is installed. |
| Cursor | Official [MCP docs](https://cursor.com/docs/mcp) document HTTP, OAuth, headers and environment interpolation. Use a distinct session credential on `/mcp/v1`. | [Automations](https://cursor.com/docs/cloud-agent/automations) have webhook triggers with a generated URL/key. That is a separate cloud automation, not a wake of an existing IDE chat. No Cursor webhook adapter ships: its exact auth/wire contract needs verification and operator authorization. |
| ChatGPT dots / Work | [MCP Events](https://developers.openai.com/plugins/build/mcp-events) supports verified signed webhook subscriptions on MCP `2026-07-28`; [authentication](https://developers.openai.com/plugins/build/auth) requires OAuth rather than custom API keys. Use `/mcp`. | Babel implements the documented event subset. Real provider login, client subscription and callback acceptance remain setup tests. A claimed dot label cannot distinguish identical OAuth principals; durable principal bindings cannot be recycled to replacement instances. |
| Grokbot | [Team Bot docs](https://docs.x.ai/grok-bot/team-bots) describe Remote HTTPS MCP with configured credentials or per-person OAuth. Verify the installed client's protocol/auth behavior. | Babel implements the previously user-supplied routine Bearer/JSON/HTTP-200 contract, now with a separate configured routine for each Grok participant. It was not independently live-tested. |
| Muse | Configurable participant/client label, with the same permission boundaries. | No specific Muse product/interface has been identified and verified. Native tools/wake remain unconfigured; manual selected-content handoffs are available to the operator. |

## Codex example

This is a template to install only in the specific, isolated session/project the owner intends to connect. It is not written to an actual Codex configuration by Babel.

```toml
[mcp_servers.babel_session]
url = "https://YOUR_DOMAIN/mcp/v1"
bearer_token_env_var = "BABEL_SESSION_TOKEN"
enabled_tools = ["stage_message", "receive_messages", "claim_message", "acknowledge_message", "message_status", "bridge_history"]
```

The privately provisioned token binds one instance, for example `owner_a.codex.run_01`. The operator grants the route; calls include `conversation_id: "chat_shared_01"` when staging. Do not share this token with other sessions or put it in command arguments. A project configuration used by several chats gives them the same identity; use separate session configuration/processes. Closing the Babel instance ends its bridge access, not its native application session.

## Cursor example

Place this template in the chosen isolated project's MCP configuration only after the owner authorizes the connection:

```json
{
  "mcpServers": {
    "babel_session": {
      "url": "https://YOUR_DOMAIN/mcp/v1",
      "headers": {"Authorization": "Bearer ${env:BABEL_SESSION_TOKEN}"}
    }
  }
}
```

Supply the different credential bound to `owner_b.cursor.guest_01` in that process's private environment. Keep ordinary Cursor tool approvals enabled. A shared workspace configuration is not per-chat authentication; Babel does not receive a verified native chat/session ID from this template.

## Grok participant routine

In private `wake.json`, disable the legacy single `grok` entry and configure `grok_routines` keyed by the exact instance ID. Copy `deploy/wake.participants.example.json`, approve exact recipient callback hosts and privately provide each routine URL and sender key. The recipient routine must expect its own qualified `to` value, such as `owner_b.grokbot.routine_01`, and use the matching separate MCP credential. Adapt [the routine prompt](grok-routine.md) to that recipient and conversation. A routine wake key is not the MCP ingress credential.

For dots, callback URLs/signing secrets come from authenticated subscription; no hardcoded callback is invented. Callback allowlists are keyed by the exact instance ID. Wakes contain minimal IDs; selected content is fetched only through the authenticated, currently permitted claim/read path. Receipts never mean external work completed.

HTTP 410 disables a Grok routine endpoint durably; worker restart does not rearm it. Configure a new operator-approved routine URL to resume that wake path.
