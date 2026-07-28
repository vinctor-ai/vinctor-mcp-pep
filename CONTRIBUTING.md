# Contributing

This repository is the MCP resource-side enforcement proxy (PEP): a stdio proxy
between an MCP client and the real MCP server that authorizes every
`tools/call` against a Vinctor service before forwarding it. Keep changes
scoped to that proxy and its config/CLI surface.

## Quality Gates

Before committing, run the full suite (build is included):

```bash
npm test           # build + unit + integration (node:test on dist)
npm run test:e2e   # REAL-service e2e; needs the sibling vinctor-core checkout
```

CI runs `npm test` on Node 20 and 22; PRs must be green. The e2e suite is
excluded from CI (no python core there) — when the core venv is absent it skips
with a loud banner rather than silently passing.

## Conventions

- **Test-first.** New behavior or a bug fix lands with a test that fails before
  the change and passes after.
- **Fail closed.** No change may turn a non-permit into a forward. A permit is
  verified from the response body — `decision: "permit"` **and** a non-empty
  `audit_event_id` — never inferred from a bare 200.
- **No disclosure.** Deny errors sent to the client carry no action/resource,
  grant existence, or service detail; do not interpolate them into error
  messages.
- **Transparent proxy.** Everything that is not `tools/call` passes through
  byte-faithfully; don't add rewriting for other message types.
- **Surgical diffs.** Match the surrounding style; don't refactor unrelated
  code.

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) — do not use public issues for vulnerabilities.
