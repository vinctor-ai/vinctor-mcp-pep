import { describe, it, before, after, afterEach } from "node:test";
import { strict as assert } from "node:assert";
import { createServer, type Server, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startHarness, until, settle, type Harness } from "../test/helpers.js";
import { DENY_MESSAGE } from "../src/enforce.js";

// Task 2 end-to-end: proxy + REAL child MCP server process + an in-process
// mock Vinctor service (mirrors vinctor-codex-hook test-integration style).
// The mock permits only (read, fs/allowed/notes.txt); everything else 403s,
// and `mode` flips outage / bare-200 behaviors.

const PEP_KEY = "pep_INTEG_secret";
const GRANT = "grt_INTEG_secret";
const SUBJECT = "vat_INTEG_secret";
const WORKSPACE_ID = "ws_INTEG";
const AGENT_ID = "agent_INTEG";

const ALLOWED_RESOURCE = "fs/allowed/notes.txt";

type ServiceRequest = {
  body: Record<string, unknown>;
  pepKey: string | null;
  subjectToken: string | null;
};

let service: Server;
let endpoint = "";
let mode: "normal" | "bare200" = "normal";
const serviceRequests: ServiceRequest[] = [];

// The mock grant: which (action, resource) pairs the service permits. The
// default mirrors the original suite (read of the one allowed file); PKA-100
// tests swap in broader rules (e.g. an fs/**-only grant) per test.
const DEFAULT_PERMIT = (action: unknown, resource: unknown): boolean =>
  resource === ALLOWED_RESOURCE && action === "read";
let permitRule: (action: unknown, resource: unknown) => boolean = DEFAULT_PERMIT;

before(async () => {
  service = createServer((req: IncomingMessage, res) => {
    let raw = "";
    req.on("data", (c: Buffer) => (raw += c.toString("utf8")));
    req.on("end", () => {
      const body = JSON.parse(raw) as Record<string, unknown>;
      serviceRequests.push({
        body,
        pepKey: (req.headers["x-pep-key"] as string | undefined) ?? null,
        subjectToken: (req.headers["x-subject-token"] as string | undefined) ?? null,
      });
      if (mode === "bare200") {
        // D-8 regression shape: HTTP 200 with no verifiable permit body.
        res.writeHead(200, { "Content-Type": "application/json" }).end("{}");
        return;
      }
      if (permitRule(body["action"], body["resource"])) {
        res
          .writeHead(200, { "Content-Type": "application/json" })
          .end(JSON.stringify({ decision: "permit", audit_event_id: `evt_integ_${serviceRequests.length}` }));
      } else {
        res
          .writeHead(403, { "Content-Type": "application/json" })
          .end(JSON.stringify({ decision: "deny", error: "action_denied" }));
      }
    });
  });
  await new Promise<void>((resolve) => service.listen(0, "127.0.0.1", resolve));
  endpoint = `http://127.0.0.1:${(service.address() as AddressInfo).port}`;
});

after(() => {
  service.close();
});

const envFor = (over: Record<string, string | undefined> = {}): Record<string, string | undefined> => ({
  VINCTOR_ENDPOINT: endpoint,
  VINCTOR_PEP_KEY: PEP_KEY,
  VINCTOR_GRANT_REF: GRANT,
  VINCTOR_SUBJECT_TOKEN: SUBJECT,
  VINCTOR_WORKSPACE_ID: WORKSPACE_ID,
  VINCTOR_AGENT_ID: AGENT_ID,
  ...over,
});

const toolsCall = (id: number | string, name: string, args: Record<string, unknown>): string =>
  JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });

const serverToolsCalls = (h: Harness): string[] =>
  h.serverLog().filter((l) => l.includes('"tools/call"'));

const EXPECTED_DENY = (id: number | string | null): string =>
  JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32000, message: DENY_MESSAGE } });

let h: Harness;
afterEach(async () => {
  if (h) await h.stop();
  // Drain in-flight fire-and-forget observe POSTs (blocked-unmapped audit)
  // from the finished test: the proxy deliberately does not await them, so
  // without this settle they can land AFTER the reset below and bleed into
  // the next test's serviceRequests (observed as a CI flake on PR #15).
  await settle();
  mode = "normal";
  permitRule = DEFAULT_PERMIT;
  serviceRequests.length = 0;
});

describe("tools/call gating via /v1/enforce/delegated (task 2)", () => {
  it("(a) permit: forwards the ORIGINAL line; server receives and answers", async () => {
    h = startHarness(envFor());
    const raw = toolsCall(10, "read_text_file", { path: "/allowed/notes.txt" });
    h.send(raw);
    await until(() => h.clientLines.length >= 1, "permitted tools/call response");
    // The mock MCP server echoes the raw bytes it received — byte-faithful forward.
    const res = JSON.parse(h.clientLines[0]!) as { id: number; result: { echoRaw: string } };
    assert.equal(res.id, 10);
    assert.equal(res.result.echoRaw, raw);
    assert.deepEqual(serverToolsCalls(h), [raw]);
    // Wire contract on the live path: strict body + both auth headers.
    assert.equal(serviceRequests.length, 1);
    const req = serviceRequests[0]!;
    // Exactly the real delegated contract's five fields — no more, no fewer.
    assert.deepEqual(Object.keys(req.body).sort(), [
      "action",
      "agent_id",
      "grant_ref",
      "resource",
      "workspace_id",
    ]);
    assert.deepEqual(req.body, {
      workspace_id: WORKSPACE_ID,
      agent_id: AGENT_ID,
      grant_ref: GRANT,
      action: "read",
      resource: ALLOWED_RESOURCE,
    });
    assert.equal(req.pepKey, PEP_KEY);
    assert.equal(req.subjectToken, SUBJECT);
  });

  it("(b) deny 403: client gets the JSON-RPC error, server receives ZERO tools/call", async () => {
    h = startHarness(envFor());
    h.send(toolsCall(11, "write_file", { path: "/forbidden/x.txt", content: "x" }));
    await until(() => h.clientLines.length >= 1, "deny response");
    assert.equal(h.clientLines[0], EXPECTED_DENY(11));
    // Ordering guarantee: a follow-up request is processed only after the deny
    // was decided, so once it round-trips the log is authoritative.
    h.send('{"jsonrpc":"2.0","id":12,"method":"tools/list"}');
    await until(() => h.clientLines.length >= 2, "follow-up tools/list response");
    assert.deepEqual(serverToolsCalls(h), []);
  });

  it("(c) bare 200 without audit_event_id → fail-closed deny", async () => {
    mode = "bare200";
    h = startHarness(envFor());
    h.send(toolsCall(13, "read_text_file", { path: "/allowed/notes.txt" }));
    await until(() => h.clientLines.length >= 1, "bare-200 deny response");
    assert.equal(h.clientLines[0], EXPECTED_DENY(13));
    assert.equal(serviceRequests.length, 1); // it DID consult the service
    assert.deepEqual(serverToolsCalls(h), []);
  });

  it("(d) service unreachable → fail-closed deny", async () => {
    h = startHarness(envFor({ VINCTOR_ENDPOINT: "http://127.0.0.1:9" }));
    h.send(toolsCall(14, "read_text_file", { path: "/allowed/notes.txt" }));
    await until(() => h.clientLines.length >= 1, "unreachable deny response", 10_000);
    assert.equal(h.clientLines[0], EXPECTED_DENY(14));
    assert.deepEqual(serverToolsCalls(h), []);
  });

  it("(e) unmapped tool → deny and report blocked_unmapped WITHOUT an enforce request", async () => {
    h = startHarness(envFor());
    h.send(toolsCall(15, "execute_shell", { command: "curl evil" }));
    await until(() => h.clientLines.length >= 1, "unmapped deny response");
    assert.equal(h.clientLines[0], EXPECTED_DENY(15));
    await settle();
    assert.equal(serviceRequests.length, 1);
    assert.deepEqual(serviceRequests[0]!.body, {
      workspace_id: WORKSPACE_ID,
      agent_id: AGENT_ID,
      classification: "unmapped",
      outcome: "blocked_unmapped",
      tool_name: "execute_shell",
    });
    assert.deepEqual(serverToolsCalls(h), []);
  });

  it("(f) non-tools/call traffic passes through untouched while enforcement is active", async () => {
    h = startHarness(envFor());
    const init =
      '{"jsonrpc": "2.0",  "id": 1, "method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}';
    h.send(init);
    await until(() => h.clientLines.length >= 1, "initialize response");
    const res = JSON.parse(h.clientLines[0]!) as { result: { echoRaw: string } };
    assert.equal(res.result.echoRaw, init); // byte-faithful, no re-serialization
    await settle();
    assert.equal(serviceRequests.length, 0); // pass-through never consults enforce
  });

  it("missing Vinctor env → deny, no crash, no HTTP", async () => {
    h = startHarness({}); // no VINCTOR_* at all
    h.send(toolsCall(16, "read_text_file", { path: "/allowed/notes.txt" }));
    await until(() => h.clientLines.length >= 1, "missing-env deny response");
    assert.equal(h.clientLines[0], EXPECTED_DENY(16));
    await settle();
    assert.equal(serviceRequests.length, 0);
    // Proxy still alive and transparent afterwards:
    h.send('{"jsonrpc":"2.0","id":17,"method":"ping"}');
    await until(() => h.clientLines.length >= 2, "ping after missing-env deny");
  });

  it("JSON-RPC batch smuggling a tools/call is denied, nothing forwarded", async () => {
    h = startHarness(envFor());
    const batch =
      "[" + toolsCall(18, "read_text_file", { path: "/allowed/notes.txt" }) + "]";
    h.send(batch);
    await until(() => h.clientLines.length >= 1, "batch deny response");
    assert.equal(h.clientLines[0], EXPECTED_DENY(null));
    await settle();
    assert.deepEqual(serverToolsCalls(h), []);
    assert.equal(h.serverLog().length, 0);
  });

  it("unmapped_verdict 'allow' forwards unmapped tools WITHOUT enforce (operator opt-out)", async () => {
    h = startHarness(envFor(), { unmappedVerdict: "allow" });
    const raw = toolsCall(30, "execute_shell", { command: "make build" });
    h.send(raw);
    await until(() => h.clientLines.length >= 1, "allowed unmapped tools/call response");
    const res = JSON.parse(h.clientLines[0]!) as { id: number; result: { echoRaw: string } };
    assert.equal(res.id, 30);
    assert.equal(res.result.echoRaw, raw); // byte-faithful forward
    await settle();
    assert.equal(serviceRequests.length, 0); // explicitly NOT enforced
  });

  it("unmapped_verdict 'allow' still enforces MAPPED tools (opt-out is unmapped-only)", async () => {
    h = startHarness(envFor(), { unmappedVerdict: "allow" });
    h.send(toolsCall(31, "write_file", { path: "/forbidden/x.txt", content: "x" }));
    await until(() => h.clientLines.length >= 1, "mapped deny under allow verdict");
    assert.equal(h.clientLines[0], EXPECTED_DENY(31));
    assert.equal(serviceRequests.length, 1); // it DID consult the service
    assert.deepEqual(serverToolsCalls(h), []);
  });

  it("no-disclosure: deny errors never carry action/resource/secrets", async () => {
    h = startHarness(envFor());
    h.send(toolsCall(19, "write_file", { path: "/forbidden/launch-codes.txt", content: "x" }));
    h.send(toolsCall(20, "execute_shell", { command: "id" }));
    await until(() => h.clientLines.length >= 2, "two deny responses");
    for (const line of h.clientLines) {
      // Mapped action & resource for id 19:
      assert.ok(!line.includes("write"), "action leaked");
      assert.ok(!line.includes("fs/"), "resource namespace leaked");
      assert.ok(!line.includes("launch-codes"), "path leaked");
      // Unmapped tool text for id 20:
      assert.ok(!line.includes("execute_shell"), "tool name leaked");
      // Credentials / grant:
      assert.ok(!line.includes(PEP_KEY), "PEP key leaked");
      assert.ok(!line.includes(GRANT), "grant_ref leaked");
      assert.ok(!line.includes(SUBJECT), "subject token leaked");
      assert.ok(!line.includes(endpoint), "endpoint leaked");
    }
  });
});

// ---------------------------------------------------------------------------
// PKA-100 — mapping-trust fixes, reproduced end to end against DECOY files
// only (fake credentials created by this suite; no real secret is ever read).
// ---------------------------------------------------------------------------

describe("PKA-100 (1): case-folded sensitive overlay (decoy .ENV)", () => {
  it("read_text_file('/…/.ENV') classifies secret/env and is DENIED under an fs/**-only grant", async () => {
    // Broad fs grant: every action on fs/** permits; secret/* has NO grant.
    permitRule = (_a, r) => typeof r === "string" && r.startsWith("fs/");
    // DECOY: a fake .env in a scratch dir. On a case-insensitive FS (macOS/
    // Windows default) open("<dir>/.ENV") would resolve this very file.
    const decoyDir = mkdtempSync(join(tmpdir(), "pka100-decoy-"));
    writeFileSync(join(decoyDir, ".env"), "SECRET=decoy\n");
    h = startHarness(envFor());
    h.send(toolsCall(50, "read_text_file", { path: `${decoyDir}/.ENV` }));
    await until(() => h.clientLines.length >= 1, "case-folded overlay deny");
    assert.equal(h.clientLines[0], EXPECTED_DENY(50));
    // The overlay classified the call over secret/env — the enforce request
    // asserted the SECRET resource, not fs/<path>, and the service denied it.
    assert.equal(serviceRequests.length, 1);
    assert.equal(serviceRequests[0]!.body["action"], "read");
    assert.equal(serviceRequests[0]!.body["resource"], "secret/env");
    // The call never reached the server; the decoy bytes never moved.
    assert.deepEqual(serverToolsCalls(h), []);
    for (const line of [...h.clientLines, ...h.serverLog()]) {
      assert.ok(!line.includes("SECRET=decoy"), "decoy secret content leaked");
    }
  });

  it("non-secret files still forward under the same fs/** grant (no false lockout)", async () => {
    permitRule = (_a, r) => typeof r === "string" && r.startsWith("fs/");
    h = startHarness(envFor());
    const raw = toolsCall(51, "read_text_file", { path: "/workspace/README.md" });
    h.send(raw);
    await until(() => h.clientLines.length >= 1, "non-secret read forwarded");
    const res = JSON.parse(h.clientLines[0]!) as { id: number; result: { echoRaw: string } };
    assert.equal(res.result.echoRaw, raw);
    assert.equal(serviceRequests[0]!.body["resource"], "fs/workspace/README.md");
  });
});

describe("PKA-100 (2): every JSON-RPC method is gated (no silent pass-through)", () => {
  it("resources/read of a decoy .ENV file URI is enforced as secret/env and DENIED + audited", async () => {
    permitRule = (_a, r) => typeof r === "string" && r.startsWith("fs/");
    const decoyDir = mkdtempSync(join(tmpdir(), "pka100-decoy-"));
    writeFileSync(join(decoyDir, ".env"), "SECRET=decoy\n");
    h = startHarness(envFor());
    h.send(JSON.stringify({
      jsonrpc: "2.0",
      id: 52,
      method: "resources/read",
      params: { uri: `file://${decoyDir}/.ENV` },
    }));
    await until(() => h.clientLines.length >= 1, "resources/read deny");
    assert.equal(h.clientLines[0], EXPECTED_DENY(52));
    // Enforced (and thereby audited by the service decision) — not passed through.
    assert.equal(serviceRequests.length, 1);
    assert.deepEqual(serviceRequests[0]!.body, {
      workspace_id: WORKSPACE_ID,
      agent_id: AGENT_ID,
      grant_ref: GRANT,
      action: "read",
      resource: "secret/env",
    });
    assert.equal(h.serverLog().length, 0);
  });

  it("resources/read of a permitted file URI forwards after a permit", async () => {
    permitRule = (_a, r) => typeof r === "string" && r.startsWith("fs/");
    h = startHarness(envFor());
    const raw = JSON.stringify({
      jsonrpc: "2.0",
      id: 53,
      method: "resources/read",
      params: { uri: "file:///workspace/data.csv" },
    });
    h.send(raw);
    await until(() => h.clientLines.length >= 1, "resources/read forwarded");
    const res = JSON.parse(h.clientLines[0]!) as { id: number; result: { echoRaw: string } };
    assert.equal(res.result.echoRaw, raw); // byte-faithful forward
    assert.equal(serviceRequests[0]!.body["resource"], "fs/workspace/data.csv");
  });

  it("resources/list is enforced (read mcp/resources), denied without a grant", async () => {
    h = startHarness(envFor());
    h.send('{"jsonrpc":"2.0","id":54,"method":"resources/list"}');
    await until(() => h.clientLines.length >= 1, "resources/list deny");
    assert.equal(h.clientLines[0], EXPECTED_DENY(54));
    assert.equal(serviceRequests[0]!.body["resource"], "mcp/resources");
    assert.equal(h.serverLog().length, 0);
  });

  it("an unknown method is denied AND audited as blocked_unmapped, never forwarded", async () => {
    h = startHarness(envFor());
    h.send('{"jsonrpc":"2.0","id":55,"method":"vendor/exec","params":{"cmd":"env"}}');
    await until(() => h.clientLines.length >= 1, "unknown-method deny");
    assert.equal(h.clientLines[0], EXPECTED_DENY(55));
    await settle();
    assert.equal(serviceRequests.length, 1);
    assert.deepEqual(serviceRequests[0]!.body, {
      workspace_id: WORKSPACE_ID,
      agent_id: AGENT_ID,
      classification: "unmapped",
      outcome: "blocked_unmapped",
      tool_name: "vendor/exec",
    });
    assert.equal(h.serverLog().length, 0);
  });
});

describe("PKA-100 (3): move_file enforces BOTH endpoints", () => {
  it("moving a file OUT of a protected subtree is denied under a destination-only grant", async () => {
    // Grant covers ONLY the destination subtree — the pre-fix proxy would
    // have permitted this move on the destination check alone.
    permitRule = (_a, r) => typeof r === "string" && r.startsWith("fs/public/");
    h = startHarness(envFor());
    h.send(toolsCall(56, "move_file", { source: "/vault/creds.txt", destination: "/public/creds.txt" }));
    await until(() => h.clientLines.length >= 1, "move-out deny");
    assert.equal(h.clientLines[0], EXPECTED_DENY(56));
    // The source check was consulted and denied.
    const resources = serviceRequests.map((r) => r.body["resource"]);
    assert.ok(resources.includes("fs/vault/creds.txt"), `source never enforced: ${resources.join(", ")}`);
    assert.deepEqual(serverToolsCalls(h), []);
  });

  it("a move fully inside the grant forwards after read+delete(source) and write(destination) permits", async () => {
    permitRule = (_a, r) => typeof r === "string" && r.startsWith("fs/public/");
    h = startHarness(envFor());
    const raw = toolsCall(57, "move_file", { source: "/public/a.txt", destination: "/public/b.txt" });
    h.send(raw);
    await until(() => h.clientLines.length >= 1, "move-within forwarded");
    const res = JSON.parse(h.clientLines[0]!) as { id: number; result: { echoRaw: string } };
    assert.equal(res.result.echoRaw, raw);
    assert.deepEqual(
      serviceRequests.map((r) => [r.body["action"], r.body["resource"]]),
      [
        ["write", "fs/public/b.txt"],
        ["read", "fs/public/a.txt"],
        ["delete", "fs/public/a.txt"],
      ],
    );
  });

});

describe("PKA-148: read_multiple_files enforces EVERY path", () => {
  it("THE EXPLOIT: a secret/env-only grant no longer reads the rest of the list", async () => {
    // The pre-fix proxy asked for `read secret/env` ALONE for this list, so
    // this grant read the ssh key and the ordinary file too.
    permitRule = (_a, r) => r === "secret/env";
    h = startHarness(envFor());
    h.send(toolsCall(70, "read_multiple_files", { paths: ["/repo/notes.txt", "/home/u/.env", "/home/u/.ssh/id_rsa"] }));
    await until(() => h.clientLines.length >= 1, "mixed-list deny");
    assert.equal(h.clientLines[0], EXPECTED_DENY(70));
    // The denial came from a member the grant does not cover, not from silence.
    const resources = serviceRequests.map((r) => r.body["resource"]);
    assert.ok(
      resources.includes("fs/repo/notes.txt") || resources.includes("secret/ssh"),
      `no non-covered member was ever consulted: ${resources.join(", ")}`,
    );
    assert.deepEqual(serverToolsCalls(h), []);
  });

  it("a list fully inside the grant forwards after one permit per distinct resource", async () => {
    permitRule = (a, r) =>
      a === "read" && (r === "secret/env" || r === "secret/ssh" || r === "fs/repo/notes.txt");
    h = startHarness(envFor());
    const raw = toolsCall(71, "read_multiple_files", { paths: ["/repo/notes.txt", "/home/u/.env", "/home/u/.ssh/id_rsa"] });
    h.send(raw);
    await until(() => h.clientLines.length >= 1, "mixed-list forwarded");
    const res = JSON.parse(h.clientLines[0]!) as { id: number; result: { echoRaw: string } };
    assert.equal(res.result.echoRaw, raw);
    assert.deepEqual(
      serviceRequests.map((r) => [r.body["action"], r.body["resource"]]),
      [
        ["read", "secret/env"],
        ["read", "fs/repo/notes.txt"],
        ["read", "secret/ssh"],
      ],
    );
  });

  it("an all-ordinary list is enforced per path (it used to unmap outright)", async () => {
    permitRule = (a, r) => a === "read" && typeof r === "string" && r.startsWith("fs/public/");
    h = startHarness(envFor());
    const raw = toolsCall(72, "read_multiple_files", { paths: ["/public/a.txt", "/public/b.txt"] });
    h.send(raw);
    await until(() => h.clientLines.length >= 1, "ordinary list forwarded");
    const res = JSON.parse(h.clientLines[0]!) as { id: number; result: { echoRaw: string } };
    assert.equal(res.result.echoRaw, raw);
    assert.deepEqual(
      serviceRequests.map((r) => [r.body["action"], r.body["resource"]]),
      [
        ["read", "fs/public/a.txt"],
        ["read", "fs/public/b.txt"],
      ],
    );
  });

  it("an inexpressible member denies the whole call with ZERO enforce checks", async () => {
    // `//` normalizes to nothing, so no complete requirement set exists.
    // Charging the expressible subset would authorize a call that still reads
    // the inexpressible path. The only service traffic is the blocked-unmapped
    // observation — an audit record, not an authorization.
    permitRule = () => true; // even an allow-everything PDP must never be asked
    h = startHarness(envFor());
    h.send(toolsCall(73, "read_multiple_files", { paths: ["/repo/a.txt", "//", "/home/u/.env"] }));
    await until(() => h.clientLines.length >= 1, "inexpressible-member deny");
    assert.equal(h.clientLines[0], EXPECTED_DENY(73));
    await settle();
    assert.equal(serviceRequests.length, 1, "exactly the observation, no enforce checks");
    assert.equal(serviceRequests[0]!.body["classification"], "unmapped");
    assert.equal(serviceRequests[0]!.body["outcome"], "blocked_unmapped");
    assert.deepEqual(serverToolsCalls(h), []);
  });
});

describe("PKA-149: fork_repository enforces source read + destination namespace write", () => {
  it("THE EXPLOIT: a grant covering the source repo cannot fork into an unauthorized org", async () => {
    // Everything on acme/api granted; the myorg namespace withheld. Pre-fix,
    // only github/acme/api/fork was ever sent, so the fork — and a copy of
    // acme/api's contents — landed in myorg unauthorized.
    permitRule = (_a, r) => typeof r === "string" && r.startsWith("github/acme/api/");
    h = startHarness(envFor());
    h.send(toolsCall(80, "fork_repository", { owner: "acme", repo: "api", organization: "myorg" }));
    await until(() => h.clientLines.length >= 1, "fork-into-unauthorized-org deny");
    assert.equal(h.clientLines[0], EXPECTED_DENY(80));
    const resources = serviceRequests.map((r) => r.body["resource"]);
    assert.ok(resources.includes("github/myorg/_/repo"), `destination never enforced: ${resources.join(", ")}`);
    assert.deepEqual(serverToolsCalls(h), []);
  });

  it("a fork fully inside the grant forwards after fork + source read + destination write", async () => {
    permitRule = (_a, r) =>
      r === "github/acme/api/fork" || r === "github/acme/api/contents" || r === "github/myorg/_/repo";
    h = startHarness(envFor());
    const raw = toolsCall(81, "fork_repository", { owner: "acme", repo: "api", organization: "myorg" });
    h.send(raw);
    await until(() => h.clientLines.length >= 1, "fork-within-grant forwarded");
    const res = JSON.parse(h.clientLines[0]!) as { id: number; result: { echoRaw: string } };
    assert.equal(res.result.echoRaw, raw);
    assert.deepEqual(
      serviceRequests.map((r) => [r.body["action"], r.body["resource"]]),
      [
        ["write", "github/acme/api/fork"],
        ["read", "github/acme/api/contents"],
        ["write", "github/myorg/_/repo"],
      ],
    );
  });
});
