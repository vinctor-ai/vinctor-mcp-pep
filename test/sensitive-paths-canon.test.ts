import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fsPathResource } from "../src/mapper.js";

/**
 * PKA-133 acceptance: the sensitive-path fold is canon, not adapter lore.
 *
 * `test/fixtures/sensitive-paths.json` is vendored byte-for-byte from
 * vinctor-conformance, which is the single source of truth for how a path
 * spelling classifies. The overlay is the ONLY gate behind the guarantee that
 * an operator can grant a broad `read:fs/**` while withholding `secret/**`, and
 * the same escape has been found three times (PKA-100 case/separator here,
 * PKA-106 in both hooks, PKA-133 trailing dot/space here). Running the canon
 * vectors through the REAL mapper entry point means a fold this adapter drops —
 * or invents unilaterally — fails here instead of drifting.
 *
 * The vectors are DECOY strings. This suite classifies strings; it never opens
 * a file, and must never be changed to.
 */
type Vector = { path: string; resource: string; why: string };
type Fixture = { version: number; vectors: Vector[] };

const FIXTURE_URL = new URL("../../test/fixtures/sensitive-paths.json", import.meta.url);
const PROVENANCE_URL = new URL(
  "../../test/fixtures/sensitive-paths.provenance.json",
  import.meta.url,
);
const fixtureBytes = readFileSync(FIXTURE_URL);
const fixture = JSON.parse(fixtureBytes.toString("utf8")) as Fixture;
const provenance = JSON.parse(readFileSync(PROVENANCE_URL, "utf8")) as {
  source: string;
  sha256: string;
};
const CURRENT_SENSITIVE_PATHS_SHA256 =
  "9b908c1213d041943d6d091d4ce310c9ef5794e75714235966e3748ecb5cea8c";

describe("canonical sensitive-path vectors (PKA-133)", () => {
  it("the vendored fixture matches its recorded provenance hash", () => {
    // Byte-identical copies only prove parity at copy time. This pins the
    // vendored bytes to the canonical source, so editing the fixture in THIS
    // repo without re-vendoring fails CI instead of drifting silently from the
    // canon and the sibling adapters (PKA-132).
    const actual = createHash("sha256").update(fixtureBytes).digest("hex");
    assert.equal(provenance.sha256, CURRENT_SENSITIVE_PATHS_SHA256);
    assert.equal(
      actual,
      CURRENT_SENSITIVE_PATHS_SHA256,
      `vendored fixture does not match ${provenance.source}; re-vendor from vinctor-conformance ` +
        "and update sha256 in sensitive-paths.provenance.json (and every sibling adapter)",
    );
  });

  it("records where the canonical fixture came from", () => {
    assert.match(provenance.source, /^github\.com\/pkachuc\/vinctor-conformance@[0-9a-f]{7,40} /);
  });

  it("loads a non-trivial fixture set", () => {
    assert.equal(fixture.version, 1);
    assert.ok(fixture.vectors.length >= 50, `only ${fixture.vectors.length} vectors`);
  });

  it("pins BOTH directions, so the fold cannot be 'classify everything as a secret'", () => {
    const secrets = fixture.vectors.filter((v) => v.resource.startsWith("secret/"));
    const files = fixture.vectors.filter((v) => v.resource.startsWith("fs/"));
    assert.ok(secrets.length >= 30, `only ${secrets.length} secret vectors`);
    assert.ok(files.length >= 15, `only ${files.length} fs vectors`);
    assert.ok(
      files.some((v) => /[. ]$/.test(v.path)),
      "no fs vector carries the trailing dot/space the fold strips",
    );
  });

  for (const v of fixture.vectors) {
    it(`${JSON.stringify(v.path)} → ${v.resource} (${v.why})`, () => {
      assert.equal(fsPathResource(v.path), v.resource);
    });
  }
});
