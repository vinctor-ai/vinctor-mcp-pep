# Roadmap

> vinctor-mcp-pep — work recognized after the first slice (stdio proxy,
> fail-closed `tools/call` enforcement, client-config rewrite). **Not a release
> commitment**; priorities shift on operator signal.

Decision record: vinctor-core
[`docs/decisions/0011-mcp-resource-side-pep.md`](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/decisions/0011-mcp-resource-side-pep.md).

## Next

- **HTTP / SSE transports** — the proxy is stdio-only today; remote MCP servers
  need the same enforcement seam.
- **Tool-schema pinning** (ADR 0011 follow-up) — detect a server changing a
  tool's semantics after listing, instead of trusting the name alone.
- **Mapping-table growth** — the built-in `tools/call` mapper is intentionally
  small; extend it per real server usage rather than reaching for
  `unmapped_verdict: "allow"`.
- **Config-rewrite generalization** — `install`/`uninstall` handle the
  Claude Desktop / Cursor `mcpServers` shape; other client config formats are
  candidates as they show up.
- **Config-integrity self-check** — a `verify` command that confirms an
  installed client config still routes every server entry through this proxy
  (today: `install --dry-run` + diff, per the README's *Config integrity*
  section).
- **First npm publish** — publish-ready; publishing is a maintainer step.

## Out of scope (affirmed)

- Sandboxing / OS-level isolation — keeping the proxy on the path is the
  deployment's job (README *Config integrity*).
- LLM-based classification of tool calls.
- Holding or injecting credentials.
- Approval workflows / human-in-the-loop prompts.
