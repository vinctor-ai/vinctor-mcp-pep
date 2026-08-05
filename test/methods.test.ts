import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { decideMethod } from "../src/methods.js";

// PKA-100: every client → server JSON-RPC method is ENUMERATED. tools/call has
// its own gate; protocol lifecycle methods pass; data-reaching methods map to
// (action, resource) checks and are enforced; EVERYTHING else is unknown and
// the proxy denies it fail-closed (never silent pass-through).

const enforce = (action: string, resource: string) => ({
  verdict: "enforce" as const,
  kind: "request" as const,
  checks: [{ action, resource }],
});

describe("decideMethod — enumeration classes", () => {
  it("tools/call routes to the tool-mapping gate", () => {
    assert.deepEqual(decideMethod("tools/call", { name: "read_text_file" }), {
      verdict: "gate-tools-call",
      kind: "request",
    });
  });

  it("protocol lifecycle methods pass through", () => {
    for (const method of [
      "initialize",
      "ping",
      "tools/list",
      "logging/setLevel",
    ]) {
      assert.deepEqual(decideMethod(method, undefined), {
        verdict: "pass",
        kind: "request",
      }, method);
    }
    for (const method of [
      "notifications/initialized",
      "notifications/cancelled",
      "notifications/progress",
      "notifications/roots/list_changed",
    ]) {
      assert.deepEqual(decideMethod(method, undefined), {
        verdict: "pass",
        kind: "notification",
      }, method);
    }
  });

  it("unknown methods are unknown → the proxy denies fail-closed", () => {
    for (const method of ["debug/eval", "vendor/exec", "resources/write", "notifications/evil", "sampling/createMessage"]) {
      assert.deepEqual(decideMethod(method, {}), { verdict: "unknown" }, method);
    }
  });
});

describe("decideMethod — resources/*", () => {
  it("resources/list and resources/templates/list → read mcp/resources", () => {
    assert.deepEqual(decideMethod("resources/list", undefined), enforce("read", "mcp/resources"));
    assert.deepEqual(decideMethod("resources/templates/list", {}), enforce("read", "mcp/resources"));
  });

  it("resources/read of a file URI enforces the fs resource", () => {
    assert.deepEqual(
      decideMethod("resources/read", { uri: "file:///workspace/notes.txt" }),
      enforce("read", "fs/workspace/notes.txt"),
    );
  });

  it("resources/read of credential material classifies secret/<kind> — case-folded (PKA-100)", () => {
    assert.deepEqual(
      decideMethod("resources/read", { uri: "file:///workspace/.env" }),
      enforce("read", "secret/env"),
    );
    assert.deepEqual(
      decideMethod("resources/read", { uri: "file:///workspace/.ENV" }),
      enforce("read", "secret/env"),
    );
    // Percent-encoded spellings decode before classification.
    assert.deepEqual(
      decideMethod("resources/read", { uri: "file:///workspace/%2Eenv" }),
      enforce("read", "secret/env"),
    );
  });

  it("resources/subscribe and unsubscribe enforce the same fs resource", () => {
    assert.deepEqual(
      decideMethod("resources/subscribe", { uri: "file:///home/u/.ssh/id_rsa" }),
      enforce("read", "secret/ssh"),
    );
    assert.deepEqual(
      decideMethod("resources/unsubscribe", { uri: "file:///a/b.txt" }),
      enforce("read", "fs/a/b.txt"),
    );
  });

  it("URI dot segments resolve BEFORE mapping — enforcement lands on the true target", () => {
    // The WHATWG URL parser resolves every dot-segment spelling (plain,
    // percent-encoded, backslashed) exactly like a compliant server does, so
    // the mapped resource is the RESOLVED path — traversal cannot aim the
    // check at one file and the server at another.
    for (const uri of ["file:///a/../b", "file:///a/%2E%2E/b", "file:///a\\..\\b"]) {
      assert.deepEqual(decideMethod("resources/read", { uri }), enforce("read", "fs/b"), uri);
    }
    assert.deepEqual(
      decideMethod("resources/read", { uri: "file:///workspace/../home/u/.ENV" }),
      enforce("read", "secret/env"),
    );
  });

  it("percent-encoded in-bounds traversal folds to the file it actually reaches (PKA-157)", () => {
    // Was unmapped. Decoding `%2E%2E%5C` gives `..\`, which folds in-bounds to
    // C:/Windows/... — exactly the file the URI denotes, so that is the
    // resource the PDP must be asked about. Refusing it named nothing.
    assert.deepEqual(
      decideMethod("resources/read", {
        uri: "file:///C:/Users/alice/%2E%2E%5C%2E%2E%5CWindows/system32/config/SAM",
      }),
      {
        verdict: "enforce",
        kind: "request",
        checks: [{ action: "read", resource: "fs/C:/Windows/system32/config/SAM" }],
      },
    );
  });

  it("unmappable URIs are unknown (non-file schemes, hosts, root, junk)", () => {
    for (const uri of [
      "https://internal/api", // non-file scheme has no fs mapping
      "postgres://db/table",
      "file://intranet-host/share/x", // a file HOST is not this host's fs
      "file:///..", // resolves to the bare root — no resource segments
      "file:///tmp/ok?/../../etc/shadow", // authorization must cover every forwarded URI byte
      "file:///tmp/ok#../../etc/shadow",
      "not a uri",
      "",
    ]) {
      assert.deepEqual(decideMethod("resources/read", { uri }), { verdict: "unknown" }, uri);
    }
    assert.deepEqual(decideMethod("resources/read", { uri: 7 }), { verdict: "unknown" });
    assert.deepEqual(decideMethod("resources/read", {}), { verdict: "unknown" });
    assert.deepEqual(decideMethod("resources/read", undefined), { verdict: "unknown" });
  });
});

describe("decideMethod — prompts/* and completion/complete", () => {
  it("prompts/list → read mcp/prompts", () => {
    assert.deepEqual(decideMethod("prompts/list", undefined), enforce("read", "mcp/prompts"));
  });

  it("prompts/get → read mcp/prompts/<name>", () => {
    assert.deepEqual(decideMethod("prompts/get", { name: "deploy-hints" }), enforce("read", "mcp/prompts/deploy-hints"));
  });

  it("prompts/get with a missing or malformed name is unknown (never guess a segment)", () => {
    for (const name of [undefined, "", "a/b", "a\\b", ".", "..", 7, "a\0b"]) {
      assert.deepEqual(decideMethod("prompts/get", { name }), { verdict: "unknown" }, String(name));
    }
  });

  it("completion/complete enforces the referenced prompt or resource", () => {
    assert.deepEqual(
      decideMethod("completion/complete", { ref: { type: "ref/prompt", name: "greet" }, argument: { name: "a", value: "v" } }),
      enforce("read", "mcp/prompts/greet"),
    );
    assert.deepEqual(
      decideMethod("completion/complete", { ref: { type: "ref/resource", uri: "file:///w/data.csv" } }),
      enforce("read", "fs/w/data.csv"),
    );
    assert.deepEqual(decideMethod("completion/complete", { ref: { type: "ref/other" } }), { verdict: "unknown" });
    assert.deepEqual(decideMethod("completion/complete", {}), { verdict: "unknown" });
  });
});
