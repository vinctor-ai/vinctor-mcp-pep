import { strict as assert } from "node:assert";
import { chmodSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { resolvePackagedProxyBin } from "./helpers.js";

describe("packaged real-core E2E binary selection", () => {
  it("fails when VINCTOR_MCP_PEP_BIN is absent instead of using the source CLI", () => {
    assert.throws(
      () => resolvePackagedProxyBin({}),
      /VINCTOR_MCP_PEP_BIN.*npm-packed install/,
    );
  });

  it("rejects a source-checkout binary even when explicitly configured", () => {
    const sourceCli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
    assert.throws(
      () => resolvePackagedProxyBin({ VINCTOR_MCP_PEP_BIN: sourceCli }),
      /outside the source checkout/,
    );
  });

  it("accepts an executable package binary outside the source checkout", () => {
    const dir = mkdtempSync(join(tmpdir(), "vinctor-mcp-pep-packed-bin-"));
    const bin = join(dir, "vinctor-mcp-pep");
    writeFileSync(bin, "#!/bin/sh\nexit 0\n");
    chmodSync(bin, 0o700);

    assert.equal(resolvePackagedProxyBin({ VINCTOR_MCP_PEP_BIN: bin }), realpathSync(bin));
  });
});
