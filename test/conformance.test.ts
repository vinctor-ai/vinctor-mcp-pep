import { describe, it, after } from "node:test";
import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { mapToolCall, isParseUnsafe } from "../src/mapper.js";

// Conformance against the Vinctor Action Taxonomy canon (vinctor-conformance).
//
// For every vendored MCP-applicable fixture this suite renders the JSON-RPC
// `tools/call` this proxy would receive for `(family, operation, params)`,
// runs the REAL mapper on the extracted (name, arguments) — exactly what
// proxy.ts gates — and asserts the mapper's `(action, resource)` equals the
// canon's `expected`. It then emits `test/conformance/result.json`.
//
// Applicability: mcp-pep sees MCP `tools/call` only (tool name + args), never
// shell. The github/filesystem/slack families apply via the MCP tables; the
// shell family (bash git/npm/docker/rm/pipe fixtures) has no surface here and
// is recorded honestly as `not-applicable` — NOT fabricated, NOT counted as
// unmapped disagreement. Note: `not-applicable` is this adapter's extension;
// the canon README's result format (and tools/matrix.mjs at 33bc8d0) knows
// only agrees|disagrees|unmapped, so matrix runs must filter or learn it.
//
// Tool-name form: fixtures render as `mcp__<server>__<tool>` — an accepted
// native spelling and the UNAMBIGUOUS one. Bare names map identically except
// where a name is claimed by two families (`delete_file`: filesystem fork vs
// classic GitHub), which stays unmapped by design — pinned in mapper.test.ts.

type Pair = { action: string; resource: string };
type WithRequirements = Pair & { alsoRequires?: Pair[] };

type Fixture = {
  id: string;
  family: "filesystem" | "github" | "shell" | "slack";
  operation: string;
  params: Record<string, unknown>;
  expected: WithRequirements;
};

type Vendored = { fixtures_version: string; source: string; fixtures: Fixture[] };

type ResultEntry = {
  id: string;
  status: "agrees" | "disagrees" | "unmapped" | "not-applicable";
  got?: WithRequirements;
};

const FIXTURES_URL = new URL("../../test/conformance/fixtures.json", import.meta.url);
const PROVENANCE_URL = new URL(
  "../../test/conformance/fixtures.provenance.json",
  import.meta.url,
);
const RESULT_URL = new URL("../../test/conformance/result.json", import.meta.url);
const CURRENT_FIXTURES_VERSION =
  "c38e7d42ab09f921e9eb93293bb532d3a27d03ac67c7b2d80850fa498fbcbe3d";
const CURRENT_FIXTURES_SHA256 =
  "3e8462d41c5da95bd9350e14246b0d8f57f0f082ced99ccba58f802dd988214d";

const fixtureBytes = readFileSync(FIXTURES_URL);
const vendored = JSON.parse(fixtureBytes.toString("utf8")) as Vendored;
const provenance = JSON.parse(readFileSync(PROVENANCE_URL, "utf8")) as {
  source: string;
  sha256: string;
};

const requiredKeys = (mapping: WithRequirements): string[] =>
  [...new Set([
    `${mapping.action} ${mapping.resource}`,
    ...(mapping.alsoRequires ?? []).map(
      (requirement) => `${requirement.action} ${requirement.resource}`,
    ),
  ])].sort();

// ---------------------------------------------------------------------------
// Native input construction.
//
// The canon's `params` are language-neutral; each builder produces the
// `tools/call` params this proxy would actually see from an MCP client for
// that operation. Path-typed params are in resource-path form (no leading
// slash) per the canon README; natively they arrive as absolute paths.
// ---------------------------------------------------------------------------

const str = (v: unknown): string => String(v);

// Canon operation → native MCP filesystem tool name (identity in canon v1).
function filesystemInput(f: Fixture): { name: string; args: Record<string, unknown> } {
  const p = f.params;
  if (f.operation === "move_file") {
    return {
      name: "mcp__filesystem__move_file",
      args: { source: `/${str(p.source)}`, destination: `/${str(p.destination)}` },
    };
  }
  return { name: `mcp__filesystem__${f.operation}`, args: { path: `/${str(p.path)}` } };
}

// Canon operation → native MCP github tool name (identity; params are already
// in the server's parameter vocabulary).
function githubInput(f: Fixture): { name: string; args: Record<string, unknown> } {
  return { name: `mcp__github__${f.operation}`, args: { ...f.params } };
}

// Canon operation → native slack tool spelling. `get_messages` binds to the
// reference server's channel-history read; `send_message` to the korotovsky
// server's add-message tool (both per the canon's alias notes).
function slackInput(f: Fixture): { name: string; args: Record<string, unknown> } {
  const p = f.params;
  const ch = { channel_id: str(p.channel) };
  switch (f.operation) {
    case "list_channels":
      return { name: "mcp__slack__slack_list_channels", args: {} };
    case "get_messages":
      return { name: "mcp__slack__slack_get_channel_history", args: { ...ch, limit: 20 } };
    case "conversations_history":
      return { name: "mcp__slack__conversations_history", args: ch };
    case "post_message":
      return { name: "mcp__slack__slack_post_message", args: { ...ch, text: str(p.text) } };
    case "send_message":
      return { name: "mcp__slack__conversations_add_message", args: { ...ch, payload: str(p.text) } };
    case "reply":
      return {
        name: "mcp__slack__slack_reply_to_thread",
        args: { ...ch, thread_ts: str(p.thread_ts), text: str(p.text) },
      };
    case "add_reaction":
      return {
        name: "mcp__slack__slack_add_reaction",
        args: { ...ch, timestamp: str(p.timestamp), reaction: str(p.emoji) },
      };
    default:
      throw new Error(`no native builder for slack operation: ${f.operation}`);
  }
}

// Render the JSON-RPC tools/call and extract (name, arguments) the way
// proxy.ts's gate does before calling the mapper.
function classify(f: Fixture): ResultEntry {
  const built =
    f.family === "filesystem" ? filesystemInput(f) :
    f.family === "github" ? githubInput(f) :
    slackInput(f);
  const request = {
    jsonrpc: "2.0" as const,
    id: 1,
    method: "tools/call",
    params: { name: built.name, arguments: built.args },
  };
  const mapped = mapToolCall(request.params.name, request.params.arguments);
  // PKA-159: both refusals report as "unmapped" to the matrix — the canon only
  // says no pair may be charged. The DIFFERENCE (hard deny vs the operator's
  // unmapped escape hatch) is a proxy behaviour, pinned in proxy/mapper tests.
  if (mapped === null || isParseUnsafe(mapped)) return { id: f.id, status: "unmapped" };
  const got: WithRequirements = {
    action: mapped.action,
    resource: mapped.resource,
    ...(mapped.alsoRequires && mapped.alsoRequires.length > 0
      ? {
          alsoRequires: mapped.alsoRequires.map((requirement) => ({
            action: requirement.action,
            resource: requirement.resource,
          })),
        }
      : {}),
  };
  const agrees =
    got.action === f.expected.action &&
    got.resource === f.expected.resource &&
    JSON.stringify(requiredKeys(got)) === JSON.stringify(requiredKeys(f.expected));
  return { id: f.id, status: agrees ? "agrees" : "disagrees", got };
}

describe("canon conformance (vinctor-conformance fixtures)", () => {
  const results = new Map<string, ResultEntry>();
  const mcpFixtures = vendored.fixtures.filter((f) => f.family !== "shell");
  const shellFixtures = vendored.fixtures.filter((f) => f.family === "shell");

  after(() => {
    // Emit the per-adapter result file (shell rows carry the honest
    // not-applicable marker; see the header note on matrix compatibility).
    const sorted = [...vendored.fixtures]
      .map((f) => results.get(f.id) ?? { id: f.id, status: "unmapped" as const })
      .sort((a, b) => a.id.localeCompare(b.id));
    const out = { adapter: "mcp-pep", fixtures_version: vendored.fixtures_version, results: sorted };
    writeFileSync(RESULT_URL, JSON.stringify(out, null, 2) + "\n");
  });

  it("vendored fixture set is intact (93 fixtures, current canon digest)", () => {
    assert.equal(provenance.source, vendored.source);
    assert.equal(provenance.sha256, CURRENT_FIXTURES_SHA256);
    assert.equal(
      createHash("sha256").update(fixtureBytes).digest("hex"),
      CURRENT_FIXTURES_SHA256,
    );
    assert.equal(vendored.fixtures_version, CURRENT_FIXTURES_VERSION);
    assert.equal(vendored.fixtures.length, 93);
    const ids = new Set(vendored.fixtures.map((f) => f.id));
    assert.equal(ids.size, vendored.fixtures.length, "fixture ids must be unique");
    assert.equal(mcpFixtures.length, 58, "MCP-applicable fixtures (github+filesystem+slack)");
    assert.equal(shellFixtures.length, 35, "shell fixtures (not applicable to an MCP proxy)");
  });

  it("move_file reports the complete required set to the matrix", () => {
    const fixture = vendored.fixtures.find((entry) => entry.id === "filesystem-move-file");
    assert.ok(fixture, "filesystem-move-file fixture must exist");
    const entry = classify(fixture);
    assert.equal(entry.status, "agrees");
    assert.ok(entry.got);
    assert.deepEqual(requiredKeys(entry.got), requiredKeys(fixture.expected));
    assert.equal(entry.got.alsoRequires?.length, 2);
  });

  for (const f of mcpFixtures) {
    it(`${f.id} → ${f.expected.action}:${f.expected.resource}`, () => {
      const entry = classify(f);
      results.set(f.id, entry);
      assert.equal(
        entry.status,
        "agrees",
        `expected ${f.expected.action}:${f.expected.resource}, got ${
          entry.got ? `${entry.got.action}:${entry.got.resource}` : "unmapped"
        }`,
      );
    });
  }

  it("shell fixtures are not applicable (mcp-pep gates MCP tools/call only, never shell)", () => {
    for (const f of shellFixtures) {
      results.set(f.id, { id: f.id, status: "not-applicable" });
    }
    assert.equal(shellFixtures.length, 35);
  });
});
