# vinctor-mcp-pep

Vinctor's MCP enforcement proxy (PEP). A stdio proxy that sits between an MCP
client and the real MCP server and authorizes every client → server JSON-RPC
request against a Vinctor service before forwarding it. `tools/call` is gated
through the tool mapper; data-reaching methods (`resources/*`, `prompts/*`,
`completion/complete`) are enforced through the method policy; enumerated
protocol lifecycle traffic (initialize, ping, tools/list, client → server
notifications, replies to server-initiated requests) and correlated server →
client output pass through byte-faithfully within the newline-framed message ceiling.
The default ceiling is 8 MiB in each direction (`ProxyOptions.maxLineBytes` can
set a different bound for embedded use); an oversized line is dropped whole
before parsing or forwarding. Parser-ambiguous messages and server requests
whose correlation identifiers exceed the bounded tracking budget are also
dropped whole. Anything else — unknown methods, JSON-RPC
batches, unclassifiable lines — is denied or dropped fail-closed, never silently
forwarded.

```
                 stdio                       stdio
 MCP client  ───────────►  vinctor-mcp-pep ───────────►  real MCP server
 (agent)     ◄───────────  (this proxy)    ◄───────────  (spawned child)
                                 │
                                 │  POST /v1/enforce/delegated
                                 ▼
                          Vinctor service
                       permit / deny (audited)
```

Every gated request is mapped to one or more Vinctor `(action, resource)`
checks, each sent to `POST {VINCTOR_ENDPOINT}/v1/enforce/delegated`. Only a
verifiable permit — HTTP 200 whose body has `decision: "permit"` **and** a
`audit_event_id` containing at least one ASCII alphanumeric — counts, and **every** check must permit before
the call forwards. Anything else (deny, HTTP error, unreachable service,
malformed body, unmapped tool, missing configuration) fails closed: the client
receives a JSON-RPC error (`code -32000`) and the call never reaches the
server. Deny errors carry no action/resource, grant, or service detail.

### What maps to what

- `tools/call` maps through the tool tables (filesystem, github, slack
  families). Filesystem paths that denote credential material (`.env`, ssh
  keys, cloud-credential files) classify over `secret/<kind>` instead of
  `fs/<path>`. The match folds each path segment three ways, because host
  filesystems resolve more spellings to the same file than a literal string
  comparison does: **case** (default macOS/Windows volumes are
  case-insensitive), **separators** (Windows treats `\` as one), and
  **trailing `.` and ` `** (Win32 `CreateFile` strips them from each
  component). So `.ENV`, `.SSH\ID_RSA`, `.env `, `.env.` and
  `C:\workspace\.env ` all classify as the secret. A broad `fs/**` grant
  therefore never quietly covers credential material in any of those
  spellings. The fold is unconditional — it only ever classifies *more*
  spellings as secrets, so it is fail-closed on every host — and it governs
  matching only: a non-sensitive path still maps to `fs/<path>` verbatim.
  The vectors are canon (`vinctor-conformance`
  `fixtures/sensitive-paths.json`, vendored and sha256-pinned under
  `test/fixtures/`).
- `move_file` requires **both endpoints**: read + delete on the source and
  write on the destination (a move discloses the source at a new location,
  removes it, and creates destination state). A grant covering only the
  destination can no longer move files out of a protected subtree.
- `resources/read`, `resources/subscribe`, `resources/unsubscribe` map their
  `file:` URI through the same path pipeline (secret overlay included);
  non-`file:` URIs are unmapped. `resources/list` and
  `resources/templates/list` map to `read` on `mcp/resources`; `prompts/list`
  to `read` on `mcp/prompts`; `prompts/get` and prompt completions to `read`
  on `mcp/prompts/<name>`.
- Every other method is unmapped and denied fail-closed (see `--config`).

## Provision the delegated-enforce credential

Create a PEP key in the same workspace as the subject grant. The raw key is
printed once, so move it directly into the proxy process environment:

```sh
export VINCTOR_DB="$HOME/.vinctor/vinctor.sqlite"
export VINCTOR_WORKSPACE_ID="ws_local"
export VINCTOR_PEP_ID="mcp_proxy"

PEP_JSON="$(
  vinctor operator keys create pep \
    --pep-id "$VINCTOR_PEP_ID" \
    --db "$VINCTOR_DB" \
    --workspace-id "$VINCTOR_WORKSPACE_ID" \
    --json
)"
export VINCTOR_PEP_KEY="$(printf '%s\n' "$PEP_JSON" | jq -r .raw_key)"
```

Then point the proxy at the running service and the subject grant. Fresh
Vinctor installations require a registered boundary by default; use the
`VINCTOR_BOUNDARY_ID` printed by `vinctor local start --boundary-name
mcp-proxy-local --boundary-runtime mcp --boundary-type stdio-proxy`, or the id
of the active boundary registered for this PEP:

```sh
export VINCTOR_ENDPOINT="http://127.0.0.1:8765"
export VINCTOR_AGENT_ID="agent_local"
export VINCTOR_GRANT_REF="grt_local"
export VINCTOR_BOUNDARY_ID="bnd_local"
```

The proxy sends the PEP key as `X-PEP-Key` and the boundary id as
`X-Vinctor-Boundary-Id` on every `POST /v1/enforce/delegated` request. The
workspace and agent values in the request are subject assertions; the trusted
PEP workspace comes only from the authenticated key.

## Install / run

Place the proxy in front of the real server command after `--`:

```sh
npx vinctor-mcp-pep -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

In an MCP client config, replace the server command with the proxy:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["vinctor-mcp-pep", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
    }
  }
}
```

### `install` / `uninstall` — client-config rewrite

`install` rewrites **every stdio** server entry of a standard MCP client config
(Claude Desktop / Cursor style) to launch through this proxy, so no stdio
server in that config can be reached except via the enforcement path:

```sh
vinctor-mcp-pep install --client-config ~/Library/Application\ Support/Claude/claude_desktop_config.json
vinctor-mcp-pep install --client-config <path> --dry-run   # print the result, write nothing
vinctor-mcp-pep uninstall --client-config <path>           # restore from the backup
```

- Each entry's `command` becomes the absolute path of this proxy's bin and its
  `args` become `["--", <original command>, ...<original args>]`; `env` and any
  other entry keys are preserved untouched.
- **Remote url-based entries are NOT gated.** A stdio proxy cannot sit on an
  SSE / streamable-HTTP connection (e.g. Cursor's `{"url": …}` servers), so
  `install` leaves them untouched and prints a one-line stderr warning naming
  them. An entry with both `command` and `url` is ambiguous and fails the
  whole rewrite.
- **Idempotent**: running `install` twice never double-wraps.
- The first `install` writes a sibling backup `<path>.vinctor-backup.json` with
  the original file. An existing backup is never overwritten — it is the
  `uninstall` source of truth. `uninstall` restores entries from it (servers
  added after install are mechanically unwrapped; deleted ones are not
  resurrected) and removes the consumed backup. Before any rewrite, an existing
  backup must be valid, structurally restorable, and unwrapped. If the backup is
  missing while the live config is already wrapped, `install` stops instead of
  recording the wrapped config as the original; `uninstall` likewise stops
  before writing if any server would remain wrapped.
- Malformed or missing config → exit 2 with a one-line error and **no** partial
  write (all writes are atomic temp-file + rename).

### `--config` — unmapped-tool verdict

By default a `tools/call` whose tool the built-in mapper does not know is
**denied fail-closed without consulting the service** (the attempt is
best-effort reported to `/v1/observe` as `blocked_unmapped`). A proxy config
file can opt out for those unmapped tools:

```sh
vinctor-mcp-pep --config /etc/vinctor-mcp-pep.json -- <server-cmd> [args...]
```

```json
{ "unmapped_verdict": "allow" }
```

> **Warning — this weakens the guarantee.** `"allow"` forwards unmapped
> `tools/call` requests to the server **without any Vinctor enforcement or
> audit**. It is an explicit operator opt-out per ADR 0011 for servers whose
> tools are not yet in the mapping table. Every unmapped tool becomes an
> unaudited side door; prefer extending the mapping. Unknown JSON-RPC methods
> remain fail-closed, and mapped tools plus enumerated data-reaching methods
> remain enforced.

A malformed config file or an unknown `unmapped_verdict` value fails closed:
the proxy keeps the default deny and writes one warning line to stderr.

## Environment

| Variable | Required | Purpose |
| --- | --- | --- |
| `VINCTOR_ENDPOINT` | yes | Base URL of the Vinctor service |
| `VINCTOR_PEP_KEY` | yes | `pep_…` key, sent as `X-PEP-Key` |
| `VINCTOR_GRANT_REF` | yes | Grant reference sent in the enforce body |
| `VINCTOR_WORKSPACE_ID` | yes | Asserted subject workspace, sent in the enforce body |
| `VINCTOR_AGENT_ID` | yes | Asserted subject agent, sent in the enforce body |
| `VINCTOR_BOUNDARY_ID` | for fresh Core installs | Registered boundary id, sent as `X-Vinctor-Boundary-Id` |
| `VINCTOR_SUBJECT_TOKEN` | no | `vat_…` subject token, sent as `X-Subject-Token` |
| `VINCTOR_SUBJECT_TOKEN_POP_SECRET` | no | `pop_secret` from `agent token mint --pop`; see below |
| `VINCTOR_SUBJECT_TOKEN_ID` | no | `vtk_…` token id of that same token; see below |

Missing required configuration is a fail-closed deny for every `tools/call`
(the proxy keeps running and stays transparent for everything else).

### Proof-of-possession (PoP)

When **both** `VINCTOR_SUBJECT_TOKEN_POP_SECRET` and `VINCTOR_SUBJECT_TOKEN_ID`
are set, every enforce request also carries `X-Subject-Token-Proof`: a fresh
HMAC proof (new nonce per request) binding this exact call's action and
resource to the token. This is what makes the proxy work with PoP-bound tokens
and under the `require-pop` mandate, where a bearer-only token is rejected.
Mint the pair with `vinctor agent token mint --grant-ref … --audience <pep-id>
--pop` and copy `pop_secret` and `token_id` from its output. If only one of
the two variables is set, no proof header is sent (never a partial proof); the
server then decides on the bearer token alone.

## Scope and honesty

This proxy is non-bypassable for the MCP path only, under the ADR 0011
preconditions (the client's only route to the server is this proxy's stdio).
It is not a sandbox: side doors around MCP — direct shell or network access,
ambient credentials already in the environment — are out of scope. Unknown
methods are always denied; unmapped tools are denied by default. The mapping
table is intentionally small in this slice. The sensitive-path overlay matches
path STRINGS, folded per segment for case, separators, and the trailing `.`/` `
Win32 strips — it does not resolve them against the live filesystem. A symlink
or hardlink whose name is innocent but whose target is credential material, a
Unicode-lookalike name, or an 8.3 short name requires realpath resolution to
catch, which this proxy does not do yet.

Locally blocked unmapped calls are submitted to `/v1/observe` through a bounded
best-effort queue. That path deliberately does not delay the deny or treat any
HTTP response as an authorization result; delivery failure therefore creates an
audit gap rather than changing enforcement. The queue is lossy under sustained
overflow, and the loss is caller-influenced: unmapped calls are denied locally
with no PDP round-trip, so an agent can emit them faster than they can be
POSTed, and once the queue is full every further observation is dropped until it
drains. Overflow drops the newest rather than the oldest — so a decoy burst
cannot evict an observation already queued ahead of it — but an agent that keeps
the queue full can still suppress observations of its own *subsequent* calls. No
eviction policy makes this lossless; the bound exists so observation cannot
exhaust memory. Every drop is reported on stderr with a running dropped-count
(PKA-131), so the gap is visible rather than silent. Malformed UTF-8/JSON and oversized
frame floods are represented only by coalesced, lossy stderr diagnostics, not
durable `/v1/observe` events. Operators who need durable transport-abuse evidence
must capture it outside this process.

JSON-RPC batches and messages with duplicate object keys are parser-ambiguous,
so the proxy denies them with `id: null` instead of trusting a possibly
ambiguous request id. Clients must treat that response as a connection-level
protocol failure rather than waiting for a response carrying the original id.

## Config integrity

The proxy enforces the `tools/call` requests it *receives*. It cannot enforce a
change to the config that decides whether it is on the path at all. Two files
are part of the trust boundary and must be protected outside the proxy:

- **The MCP client config** (`mcpServers` JSON). It names the `command`/`args`
  the client launches. An actor who can edit it can point `command` back at the
  bare server and remove the proxy entirely.
- **The `--config` proxy file** (`unmapped_verdict`). An actor who can edit it
  can flip `unmapped_verdict` to `"allow"` and turn every unmapped tool into an
  unaudited side door.

Mitigations, in order of leverage:

1. **Keep both files outside the agent's write scope.** If the agent runtime the
   proxy protects can also edit these files, the guarantee is self-referential.
   Store them on a root-owned path, a read-only mount, or a directory excluded
   from the agent's filesystem grant — somewhere the protected agent cannot
   write.
2. **Pin the approved proxy command.** The `command`/`args` that launch the proxy
   are what make it non-bypassable. Treat that launcher line the way you treat
   any privileged command: review it, and alert on changes to it.
3. **Verify integrity at startup.** Re-run
   `install --client-config <path> --dry-run` (idempotent, writes nothing) and
   check two things:
   - **The exit code.** A dry run exits non-zero and names any entry carrying
     the `x-vinctor-mcp-pep` marker whose `command` is not this proxy. That
     marker is written by `install`, but it is only a marker: anything able to
     write the client config can add it, so it is never evidence that an entry
     is gated. The rule install applies is deliberately narrow — **it accepts a
     command only if install itself wrote that exact string**, byte-identical to
     the absolute path it writes. It does *not* try to prove the command names
     the same file: realpath equality would hold in the *installer's*
     environment while the entry carries the *client's* (an entry's own
     `"env": {"PATH": "..."}` sends the client's spawn elsewhere), and an
     attacker-owned symlink can be swapped after the check and back before the
     next one. Byte equality has neither gap.
   - **The output.** The printed JSON is what the file *should* contain. Diff it
     against the file: any difference means the current config is not what a
     correct install produces. Entries this installer wrote have
     `args[0] === "--"`; flags smuggled in before that separator (e.g. an
     attacker-chosen `--config`, which sets `unmapped_verdict`) make an entry
     unrecognised, so it is re-wrapped and shows up in the diff.

   A plain `install` (no `--dry-run`) repairs all of the above by re-wrapping,
   and exits 0 after printing the same warnings. A checksum check in your launch
   script still catches edits neither pass inspects.

   Two consequences worth knowing:
   - **A moved npm prefix causes a double-wrap.** The old absolute path is no
     longer the string install writes, so the entry is wrapped again around
     itself. This is cosmetic and fail-closed: the outer command is the proxy
     that is actually running, and it enforces every call. `uninstall` restores
     the original entry from the backup as usual.
   - **An entry whose `env` or `envFile` could redirect the proxy is refused,
     not repaired.** Once an entry is wrapped, the client launches *the proxy*
     with that entry's environment — so a field that reads as server
     configuration is proxy configuration. `install`, `--dry-run` and
     `uninstall` all exit non-zero, name the entry and the field, and change
     nothing. Refused, case-insensitively (Windows environment variables are
     case-insensitive, and `Path` is the conventional spelling):
     - **Any `VINCTOR_*` key.** This is the important one. The proxy reads its
       endpoint, PEP key, grant ref, workspace/agent id and subject token from
       its environment, so `"env": {"VINCTOR_ENDPOINT": "http://attacker/"}` on
       an otherwise perfectly-wrapped entry points every authorization check at
       a PDP that answers "permit", and sends the audit stream there too. **The
       proxy's configuration is the operator's to set, not the config file's.**
       Matched by prefix — the same rule that already strips `VINCTOR_*` from
       the wrapped server's environment — so a setting added in a later release
       is covered without editing a list.
     - **Loader keys**: `NODE_OPTIONS`, `NODE_PATH`, `PATH`, `LD_PRELOAD`,
       `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`.
     - **Trust roots**: `NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED`,
       `SSL_CERT_FILE`, `SSL_CERT_DIR`.
     - **`envFile` in any form.** Cursor honours it, and it can supply exactly
       the keys above from a file. It is refused rather than read, because
       reading it would mean checking a file at install time that the client
       re-reads at launch — the same check-then-launch gap that makes proving
       the *command* by resolution unusable.

     Nothing is stripped silently: that would delete operator configuration
     without saying so. Everything else in `env` — the server's own tokens and
     settings — is passed through untouched, as is `cwd` (it cannot change what
     the proxy executes, because the command is an absolute path).

     **If one of these is legitimately yours**, move it out of the entry and
     re-run `install`: put it in the environment that launches the MCP client,
     or on the server command itself so it reaches the server rather than the
     proxy — e.g. `"command": "/usr/bin/env", "args": ["FOO=bar",
     "real-server", …]`. **Cursor users with an `envFile`**: inline those
     variables into the entry's `env` (they pass through untouched unless they
     are on the refused list), or export them in the environment you launch
     Cursor from.

   None of this defends against an attacker who can overwrite the proxy binary
   itself, or the `node` that runs it. If they can do that, they are already
   inside the trust boundary and nothing in this section helps. Mitigation 1 —
   keeping these paths outside the agent's write scope — is what that depends
   on.
4. **Audit config changes.** Put both files under version control or a
   file-integrity monitor so an edit is visible after the fact even if it slips
   past the checks above.

### Locking the files down (example)

"The agent cannot write this file" has to hold on **every** path — shell,
scripts, any tool — which only the OS can guarantee. The classic shape: config
readable by the client, writable only through an operator step.

```sh
CFG="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
sudo chown root:staff "$CFG" && sudo chmod 644 "$CFG"

# Delete/rename/replace rights come from the parent DIRECTORY, not the file —
# lock it too, or the file can simply be swapped out.
sudo chown root:staff "$(dirname "$CFG")" && sudo chmod 755 "$(dirname "$CFG")"

# Stronger: immutable flags (clear them for operator edits)
sudo chflags schg "$CFG"    # macOS   (undo: sudo chflags noschg)
# sudo chattr +i "$CFG"     # Linux   (undo: sudo chattr -i)
```

Two trade-offs to accept consciously: the client app's own settings UI can no
longer edit its config either (config changes become an operator step), and if
the launching user has passwordless `sudo`, none of this holds.

### Defense-in-depth on mediated paths

Where the agent's file access is itself mediated — a Vinctor hook on the
harness's file tools, or a filesystem MCP server behind this proxy — you can
additionally map writes to these config paths to an action you never grant
(e.g. `**/claude_desktop_config.json` → `write:mcp/client-config`). The attempt
is then denied **and audited**, which OS permissions alone do not give you. This
covers only mediated calls — an unmediated shell write bypasses it — so it is a
tripwire on top of the OS-level lock, not a substitute for it.

None of this is enforced by the proxy itself — it is operator responsibility,
the same way a firewall cannot protect a rule file that anyone can rewrite. The
proxy's job is to fail closed on every call it sees; keeping it on the path is
the deployment's job.

## Develop

```sh
npm test           # build + unit + integration tests (node:test on dist)
npm pack --pack-destination /tmp/vinctor-mcp-package
npm install --prefix /tmp/vinctor-mcp-install /tmp/vinctor-mcp-package/vinctor-mcp-pep-*.tgz
VINCTOR_MCP_PEP_BIN=/tmp/vinctor-mcp-install/node_modules/.bin/vinctor-mcp-pep \
  npm run test:e2e
```

`npm run test:e2e` requires `VINCTOR_MCP_PEP_BIN` to name an executable
npm-packed install outside this source checkout; it has no source-CLI fallback.
It boots a throwaway Vinctor service from
`$VINCTOR_CORE_DIR/.venv`, provisions a PEP key
and subject token, and asserts end-to-end that permitted calls forward, denied
calls are blocked, and the audit trail records the enforcing PEP principal
separately from the subject agent. It remains a separate command because it
boots a real Python service. CI installs a full-SHA-pinned Core contract,
packs and installs the npm artifact, then runs the suite through that installed
CLI on Node 20 and 22. Updating the audit contract therefore requires updating
the Core pin and assertions together. When explicitly run without an executable
Core venv or packaged proxy binary, the command fails instead of reporting an
empty successful test run. The `prepack` lifecycle rebuilds `dist`, so a clean
`npm pack` cannot silently produce a package without the CLI.
