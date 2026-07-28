import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mapToolCall } from "../src/mapper.js";

/**
 * PKA-148 acceptance: the canonical multi-effect requirement vectors, run
 * against this adapter's REAL mapper — the same function proxy.ts gates on.
 *
 * `test/fixtures/multi-effect.json` is vendored byte-for-byte from
 * vinctor-conformance and hash-pinned by its provenance file, the same way
 * sensitive-paths.json is. Each vector states the COMPLETE set of
 * (action, resource) pairs the operation must be authorized for. Agreeing on
 * the primary pair while dropping a required one is a failure here — that is
 * the exact shape of the defect: read_multiple_files mapped only its first
 * credential-shaped path, so a grant covering any one member of the list read
 * every other member unenforced (and move_file before it, PKA-100/PKA-145).
 *
 * This suite arrives with PKA-148: mcp-pep was read-only during PKA-145, and
 * leaving it out of that unification is precisely what produced the earlier
 * drift — so the vendoring lands here now, not on the next card.
 *
 * Every credential-shaped path in the vectors is a DECOY STRING. This suite
 * classifies paths; it never opens, reads or creates any file they name.
 */

type Pair = { action: string; resource: string };
type Vector = {
  id: string;
  surface: "mcp/filesystem" | "codex/apply_patch" | "hermes/filesystem" | "hermes/patch" | "github/fork";
  operation: string;
  params: Record<string, unknown>;
  primary: Pair | null;
  requires: Pair[];
  why: string;
};
type Fixture = { version: number; vectors: Vector[] };

const FIXTURE_URL = new URL("../../test/fixtures/multi-effect.json", import.meta.url);
const PROVENANCE_URL = new URL("../../test/fixtures/multi-effect.provenance.json", import.meta.url);
const fixtureBytes = readFileSync(FIXTURE_URL);
const fixture = JSON.parse(fixtureBytes.toString("utf8")) as Fixture;
const provenance = JSON.parse(readFileSync(PROVENANCE_URL, "utf8")) as { source: string; sha256: string };
const CURRENT_MULTI_EFFECT_SHA256 =
  "7d29a8b08177b2df6acda962c2da46a33298972477b9af1f2b691036a7702a10";

/** This proxy exposes the MCP filesystem and GitHub surfaces; the rest are foreign. */
const APPLICABLE = new Set(["mcp/filesystem", "github/fork"]);

const key = (p: Pair): string => `${p.action} ${p.resource}`;
const sortedKeys = (pairs: Pair[]): string[] => [...new Set(pairs.map(key))].sort();

/** The JSON-RPC tool call this vector renders to. */
function nativeCall(v: Vector): { name: string; args: Record<string, unknown> } {
  if (v.surface === "github/fork") {
    // github params (owner/repo/organization) are identifiers, not paths.
    return { name: `mcp__github__${v.operation}`, args: { ...(v.params as Record<string, unknown>) } };
  }
  const abs = (p: unknown): string => `/${String(p)}`;
  const args =
    v.operation === "move_file"
      ? { source: abs(v.params.source), destination: abs(v.params.destination) }
      : v.operation === "read_multiple_files"
        ? { paths: (v.params.paths as unknown[]).map(abs) }
        : { path: abs(v.params.path) };
  return { name: `mcp__filesystem__${v.operation}`, args };
}

describe("canonical multi-effect vectors (PKA-148)", () => {
  it("the vendored fixture matches its recorded provenance hash", () => {
    const actual = createHash("sha256").update(fixtureBytes).digest("hex");
    assert.equal(provenance.sha256, CURRENT_MULTI_EFFECT_SHA256);
    assert.equal(
      actual,
      CURRENT_MULTI_EFFECT_SHA256,
      `vendored fixture does not match ${provenance.source}; re-vendor from vinctor-conformance ` +
        "and update sha256 in multi-effect.provenance.json (and every sibling adapter)",
    );
  });

  it("the vector set is intact and covers this adapter's surfaces", () => {
    assert.equal(fixture.version, 1);
    assert.ok(fixture.vectors.length >= 12, `only ${fixture.vectors.length} vectors`);
    const mine = fixture.vectors.filter((v) => APPLICABLE.has(v.surface));
    assert.ok(mine.length >= 7, `only ${mine.length} applicable vectors`);
    assert.ok(mine.some((v) => v.operation === "move_file" && v.requires.length === 3));
    // The read-side vectors must be present — a re-vendor that lost them
    // would silently drop the read_multiple_files contract.
    assert.ok(mine.some((v) => v.operation === "read_multiple_files" && v.requires.length === 3));
    assert.ok(mine.some((v) => v.operation === "read_multiple_files" && v.requires.length === 0));
    // PKA-149: the fork requirement set must be present too.
    assert.ok(mine.some((v) => v.operation === "fork_repository" && v.requires.length === 3));
  });

  for (const v of fixture.vectors.filter((vec) => APPLICABLE.has(vec.surface))) {
    it(`${v.id}: requires ${sortedKeys(v.requires).join(" + ") || "nothing"}`, () => {
      const { name, args } = nativeCall(v);
      const mapped = mapToolCall(name, args);
      if (v.requires.length === 0) {
        assert.equal(mapped, null, `${v.id}: must not be mapped (the proxy denies unmapped fail-closed)`);
        return;
      }
      assert.ok(mapped !== null, `${v.id}: expected a mapping`);
      assert.deepEqual({ action: mapped.action, resource: mapped.resource }, v.primary, `${v.id}: primary pair`);
      assert.deepEqual(
        sortedKeys([{ action: mapped.action, resource: mapped.resource }, ...(mapped.alsoRequires ?? [])]),
        sortedKeys(v.requires),
        `${v.id}: required set`,
      );
    });
  }

  it("the foreign-surface vectors are recorded as not-applicable, not silently dropped", () => {
    const KNOWN_FOREIGN = new Set(["codex/apply_patch", "hermes/filesystem", "hermes/patch"]);
    const other = fixture.vectors.filter((v) => !APPLICABLE.has(v.surface));
    assert.ok(other.length > 0);
    for (const v of other) {
      assert.ok(KNOWN_FOREIGN.has(v.surface), `${v.id}: unexpected foreign surface ${v.surface}`);
    }
  });
});
