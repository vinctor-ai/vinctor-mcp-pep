import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { startProxy } from "../src/proxy.js";

// The proxy authenticates to Vinctor with VINCTOR_* secrets (PEP key, subject
// token, grant ref). The real MCP server it spawns is the very component whose
// tool calls we don't fully trust — a compromised or supply-chain-tampered
// server must NOT receive the boundary's own credentials, or it could call the
// PDP directly (bypassing the gate) or exfiltrate the PEP key.
//
// This drives a child that reports which VINCTOR_* variables it can see in its
// own environment, and asserts it sees none — while a non-VINCTOR variable is
// still inherited (the sanitizer strips secrets, not the whole environment).

// Child: writes {leaked: {VINCTOR_* it sees}, sawPassthrough: bool} to argv[2].
const DUMP_ENV_SRC = [
  'const fs = require("node:fs");',
  "const leaked = {};",
  'for (const k of Object.keys(process.env)) if (k.startsWith("VINCTOR_")) leaked[k] = process.env[k];',
  'fs.writeFileSync(process.argv[2], JSON.stringify({ leaked, sawPassthrough: process.env.MCP_PEP_PASSTHROUGH === "keep-me" }));',
  "process.exit(0);",
].join("\n");

describe("child MCP server env isolation", () => {
  it("does not inherit VINCTOR_* secrets, but keeps non-secret env", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vinctor-mcp-pep-env-"));
    const childPath = join(dir, "dump-env.cjs");
    const outPath = join(dir, "child-env.json");
    writeFileSync(childPath, DUMP_ENV_SRC);

    // A VINCTOR_* secret present in the proxy PROCESS env (the pre-fix bug
    // inherited process.env wholesale, so this would leak into the child).
    process.env.VINCTOR_LEAK_PROBE = "must-not-reach-child";
    try {
      const proxy = startProxy({
        command: process.execPath,
        args: [childPath, outPath],
        clientIn: new PassThrough(),
        clientOut: new PassThrough(),
        clientErr: new PassThrough(),
        // The environment the proxy reads its own config from: VINCTOR_*
        // secrets plus a non-secret var the child legitimately needs.
        env: {
          PATH: process.env.PATH,
          MCP_PEP_PASSTHROUGH: "keep-me",
          VINCTOR_PEP_KEY: "pep_secret",
          VINCTOR_SUBJECT_TOKEN: "vat_secret",
          VINCTOR_GRANT_REF: "grt_secret",
        },
      });
      await proxy.done;

      const result = JSON.parse(readFileSync(outPath, "utf8")) as {
        leaked: Record<string, string>;
        sawPassthrough: boolean;
      };
      assert.deepEqual(result.leaked, {}, "child must see no VINCTOR_* variables");
      assert.equal(result.sawPassthrough, true, "child must still inherit non-secret env");
    } finally {
      delete process.env.VINCTOR_LEAK_PROBE;
    }
  });
});
