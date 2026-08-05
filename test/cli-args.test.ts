import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { parseCliArgs } from "../src/cli.js";

const argv = (...rest: string[]): string[] => ["node", "cli.js", ...rest];

describe("parseCliArgs", () => {
  it("parses -- <server-cmd> [args...]", () => {
    const p = parseCliArgs(argv("--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"));
    assert.deepEqual(p, {
      ok: true,
      configPath: null,
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    });
  });

  it("parses --config before --", () => {
    const p = parseCliArgs(argv("--config", "/etc/vinctor.json", "--", "node", "server.js"));
    assert.deepEqual(p, {
      ok: true,
      configPath: "/etc/vinctor.json",
      command: "node",
      args: ["server.js"],
    });
  });

  it("everything after -- belongs to the server (flags are not ours)", () => {
    const p = parseCliArgs(argv("--", "node", "--config", "srv.json"));
    assert.ok(p.ok);
    assert.equal(p.command, "node");
    assert.deepEqual(p.args, ["--config", "srv.json"]);
  });

  it("rejects missing --", () => {
    const p = parseCliArgs(argv("node", "server.js"));
    assert.ok(!p.ok);
  });

  it("rejects empty server command after --", () => {
    const p = parseCliArgs(argv("--"));
    assert.ok(!p.ok);
  });

  it("rejects --config without a value", () => {
    assert.ok(!parseCliArgs(argv("--config")).ok);
    assert.ok(!parseCliArgs(argv("--config", "--", "node")).ok);
  });

  it("rejects unknown proxy-side arguments", () => {
    assert.ok(!parseCliArgs(argv("--verbose", "--", "node")).ok);
  });
});
