# App ports and third-party mods

Babel does not depend on any application port or unofficial mod. Packaging source version strings do not verify installed runtime versions or prove that a local messaging endpoint exists.

Public GrokBot MCP projects can require a separately configured gateway or expose broad file/process access. Neither capability belongs in this minimal bridge. No mod source is copied into this repository, and no unsupported local API is guessed. Use the official Remote HTTPS MCP configuration or a separately reviewed, narrow adapter.

The Grok routine wake adapter follows the user-supplied contract described in the README. It needs an operator-configured routine endpoint and sender key; it cannot create those on behalf of the user.
