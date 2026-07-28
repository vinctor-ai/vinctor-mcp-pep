import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseProxyConfigText, loadProxyConfig } from "../src/config.js";

describe("parseProxyConfigText — unmapped_verdict", () => {
  it('absent key → deny, silent (an empty config "{}" is valid)', () => {
    assert.deepEqual(parseProxyConfigText("{}"), { unmappedVerdict: "deny", warning: null });
  });

  it('explicit "deny" → deny, silent', () => {
    assert.deepEqual(parseProxyConfigText('{"unmapped_verdict":"deny"}'), {
      unmappedVerdict: "deny",
      warning: null,
    });
  });

  it('"allow" → allow (explicit operator opt-out)', () => {
    assert.deepEqual(parseProxyConfigText('{"unmapped_verdict":"allow"}'), {
      unmappedVerdict: "allow",
      warning: null,
    });
  });

  it("unknown value → deny WITH one warning (fail-closed)", () => {
    for (const bad of ['"permit"', '"ALLOW"', "true", "1", "null", "[]"]) {
      const r = parseProxyConfigText(`{"unmapped_verdict":${bad}}`);
      assert.equal(r.unmappedVerdict, "deny", `value ${bad} must fail closed`);
      assert.ok(r.warning !== null, `value ${bad} must warn`);
    }
  });

  it("malformed JSON / non-object → deny WITH warning", () => {
    for (const text of ["{nope", '"allow"', "[]", "null"]) {
      const r = parseProxyConfigText(text);
      assert.equal(r.unmappedVerdict, "deny");
      assert.ok(r.warning !== null);
    }
  });
});

describe("loadProxyConfig", () => {
  it("null path (no --config) → deny, silent", () => {
    assert.deepEqual(loadProxyConfig(null), { unmappedVerdict: "deny", warning: null });
  });

  it("unreadable file → deny WITH warning", () => {
    const r = loadProxyConfig(join(tmpdir(), "vinctor-mcp-pep-definitely-missing.json"));
    assert.equal(r.unmappedVerdict, "deny");
    assert.ok(r.warning !== null);
  });

  it("readable allow config → allow", () => {
    const dir = mkdtempSync(join(tmpdir(), "vinctor-mcp-pep-config-"));
    const path = join(dir, "config.json");
    writeFileSync(path, '{"unmapped_verdict": "allow"}\n');
    assert.deepEqual(loadProxyConfig(path), { unmappedVerdict: "allow", warning: null });
  });
});
