# vinctor-mcp-pep — agent conventions

Vinctor's MCP enforcement proxy (PEP): `MCP client → this proxy (stdio) → real MCP
server`. Every client → server request is authorized via `POST /v1/enforce/delegated`
on the Vinctor service (`X-PEP-Key: pep_…`, optional `X-Subject-Token: vat_…`) before
it is forwarded: `tools/call` through the tool mapper, data-reaching methods
(resources/*, prompts/*, completion/complete) through the method policy
(src/methods.ts); a call may require MULTIPLE (action, resource) permits (move_file:
source read+delete AND destination write). Non-permit (deny / unreachable /
malformed / unmapped / unknown method) ⇒ a synthetic JSON-RPC error to the client;
the call NEVER reaches the server (fail-closed).

Decision record: vinctor-core `docs/decisions/0011-mcp-resource-side-pep.md` (Accepted).
Plan: vinctor-core `docs/superpowers/plans/2026-07-02-mcp-non-bypassable-pep.md`.

Locked decisions: stdio transport first (HTTP/SSE later); unmapped tools default
to fail-closed deny (policy-configurable later); tool-schema pinning is a follow-up.

Invariants (same family as the hooks):
- **Fail closed.** No error path may forward an unauthorized call. Method dispatch
  is fail-closed by ENUMERATION: unknown methods, batches, and unclassifiable
  lines are denied/dropped, never silently forwarded.
- **No disclosure**: deny errors to the client carry no grant existence, secrets,
  or classified action/resource interpolation.
- **Transparent proxy** for enumerated protocol lifecycle traffic (initialize,
  ping, tools/list, client notifications, replies to server-initiated requests)
  and server → client output within the shared newline-framed message ceiling.
  Forwarded messages stay byte-faithful; oversized, parser-ambiguous, or
  correlation-untrackable server requests are dropped whole.
- TDD (node:test), TypeScript strict, stdlib-only runtime deps where possible.
- main is human-merged only; feature branches + PRs.
