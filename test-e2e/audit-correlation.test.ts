import { describe, it, before, after } from "node:test";
import { strict as assert } from "node:assert";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startCliHarness, until, type CliHarness } from "../test/helpers.js";
import { DENY_MESSAGE } from "../src/enforce.js";

/**
 * REAL-service e2e (npm run test:e2e): boots a throwaway Vinctor service,
 * provisions a PEP key + subject token, runs the proxy with a mock MCP server
 * against the REAL /v1/enforce/delegated, and asserts the audit trail records
 * the enforcing PEP principal SEPARATELY from the subject agent (ADR 0007:
 * enforcing_principal vs agent_id). CI points VINCTOR_CORE_DIR at the pinned
 * core contract and VINCTOR_MCP_PEP_BIN at an npm-packed install. Local runs
 * must explicitly name both artifacts so an arbitrary sibling checkout cannot
 * masquerade as the versioned contract.
 */

const CORE_DIR = process.env["VINCTOR_CORE_DIR"];
if (!CORE_DIR) {
  throw new Error("real-service e2e requires VINCTOR_CORE_DIR");
}
const VINCTOR_BIN = join(CORE_DIR, ".venv", "bin", "vinctor");

const PEP_ID = "pep_mcp_proxy_e2e";
const ALLOWED_SCOPE = "read:fs/e2e-allowed/*";
const PEP_PROVISION_VERB = process.env["VINCTOR_E2E_PEP_PROVISION_VERB"] ?? "create";

if (PEP_PROVISION_VERB !== "create" && PEP_PROVISION_VERB !== "rotate") {
  throw new Error("VINCTOR_E2E_PEP_PROVISION_VERB must be create or rotate");
}

if (!existsSync(VINCTOR_BIN)) {
  throw new Error(
    `real-service e2e requires an executable vinctor-core venv at ${VINCTOR_BIN}; ` +
      "set VINCTOR_CORE_DIR to the intended pinned Core checkout",
  );
}

type AuditEvent = {
  event_id: string;
  event_type: string;
  decision: string;
  action: string;
  resource: string;
  agent_id: string;
  enforcing_principal: string | null;
  subject_token_verified: boolean;
  token_id: string | null;
};

function vinctorSync(args: string[], what: string): Record<string, unknown> {
  const res = spawnSync(VINCTOR_BIN, args, { encoding: "utf8", timeout: 30_000 });
  assert.equal(res.status, 0, `${what} failed: ${res.stderr || res.stdout}`);
  return JSON.parse(res.stdout) as Record<string, unknown>;
}

async function freePort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const address = srv.address();
      if (address === null || typeof address === "string") return reject(new Error("no port"));
      srv.close(() => resolve(address.port));
    });
  });
}

describe(
  "audit correlation against the REAL vinctor service",
  () => {
    let service: ChildProcess;
    let serviceOut = "";
    let dbPath = "";
    let endpoint = "";
    let boundaryId = "";
    let agentKey = "";
    let grantRef = "";
    let pepKey = "";
    let subjectToken = "";
    let h: CliHarness;

    before(async () => {
      const dir = mkdtempSync(join(tmpdir(), "vinctor-mcp-pep-e2e-"));
      dbPath = join(dir, "vinctor.db");
      const port = await freePort();

      // 1. Boot the throwaway service (foreground server; prints VINCTOR_* exports).
      service = spawn(
        VINCTOR_BIN,
        [
          "local",
          "start",
          "--db",
          dbPath,
          "--port",
          String(port),
          "--scope",
          ALLOWED_SCOPE,
          "--boundary-name",
          "mcp-proxy-local",
          "--boundary-runtime",
          "mcp",
          "--boundary-type",
          "stdio-proxy",
        ],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      service.stdout!.on("data", (c: Buffer) => (serviceOut += c.toString("utf8")));
      service.stderr!.on("data", (c: Buffer) => (serviceOut += c.toString("utf8")));
      await until(
        () => serviceOut.includes("listening"),
        `vinctor local start to listen (output so far: ${serviceOut.slice(0, 400)})`,
        30_000,
      );
      const exports = new Map<string, string>();
      for (const m of serviceOut.matchAll(/export (VINCTOR_[A-Z_]+)="([^"]*)"/g)) {
        exports.set(m[1] as string, m[2] as string);
      }
      endpoint = exports.get("VINCTOR_ENDPOINT") ?? "";
      boundaryId = exports.get("VINCTOR_BOUNDARY_ID") ?? "";
      agentKey = exports.get("VINCTOR_AGENT_KEY") ?? "";
      grantRef = exports.get("VINCTOR_GRANT_REF") ?? "";
      assert.ok(endpoint && boundaryId && agentKey && grantRef, `missing exports in:\n${serviceOut}`);

      // 2. Provision the PEP key (ADR 0007: local start wires no PEP key itself).
      const created = vinctorSync(
        [
          "--db",
          dbPath,
          "operator",
          "keys",
          PEP_PROVISION_VERB,
          "pep",
          "--pep-id",
          PEP_ID,
          "-o",
          "json",
        ],
        "pep key create",
      );
      pepKey = String(created["raw_key"] ?? "");
      assert.ok(pepKey.startsWith("pep_"), `unexpected create output: ${JSON.stringify(created)}`);

      // 3. Mint a subject token (audience = the PEP) so the delegated decision
      //    is identity-proven, exercising the full X-Subject-Token path.
      const minted = vinctorSync(
        ["--endpoint", endpoint, "--agent-key", agentKey, "agent", "token", "mint",
          "--grant-ref", grantRef, "--audience", PEP_ID, "-o", "json"],
        "subject token mint",
      );
      subjectToken = String(minted["token"] ?? "");
      assert.ok(subjectToken.length > 0, `unexpected mint output: ${JSON.stringify(minted)}`);

      // 4. Proxy (with its mock MCP child) pointed at the REAL service.
      h = startCliHarness({
        VINCTOR_ENDPOINT: endpoint,
        VINCTOR_PEP_KEY: pepKey,
        VINCTOR_GRANT_REF: grantRef,
        VINCTOR_WORKSPACE_ID: "ws_local",
        VINCTOR_AGENT_ID: "agent_local",
        VINCTOR_BOUNDARY_ID: boundaryId,
        VINCTOR_SUBJECT_TOKEN: subjectToken,
      });
    });

    after(async () => {
      if (h) await h.stop();
      if (service && !service.killed) {
        service.kill("SIGTERM");
        await new Promise((r) => setTimeout(r, 300));
        service.kill("SIGKILL");
      }
    });

    const auditEvents = (): AuditEvent[] => {
      const listed = vinctorSync(
        ["--db", dbPath, "operator", "audit", "list", "--limit", "50", "-o", "json"],
        "audit list",
      );
      return (listed["audit_events"] as AuditEvent[]) ?? [];
    };

    it("PERMITTED tools/call forwards, and the audit event separates PEP from subject", async () => {
      const raw = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "read_text_file", arguments: { path: "/e2e-allowed/notes.txt" } },
      });
      h.send(raw);
      await until(() => h.clientLines.length >= 1, "permitted tools/call response", 15_000);
      const res = JSON.parse(h.clientLines[0]!) as { id: number; result?: { echoRaw: string } };
      assert.equal(res.id, 1);
      assert.equal(res.result?.echoRaw, raw, `expected forward, got: ${h.clientLines[0]}`);

      const permit = auditEvents().find(
        (e) => e.decision === "permit" && e.resource === "fs/e2e-allowed/notes.txt",
      );
      assert.ok(permit, "no permit audit event recorded for the forwarded call");
      assert.equal(permit.event_type, "action_permitted");
      assert.equal(permit.action, "read");
      // ADR 0007 correlation: WHO ASKED (the PEP) is recorded separately from
      // WHO THE DECISION IS ABOUT (the subject agent) — and they differ.
      assert.equal(permit.enforcing_principal, PEP_ID);
      assert.equal(permit.agent_id, "agent_local");
      assert.notEqual(permit.enforcing_principal, permit.agent_id);
      // Subject token was presented and verified:
      assert.equal(permit.subject_token_verified, true);
      assert.ok(permit.token_id, "subject-token-verified event should carry the token_id");
    });

    it("DENIED tools/call is blocked and the deny is audited with the PEP principal", async () => {
      const linesBefore = h.clientLines.length;
      h.send(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: {
            name: "write_file",
            arguments: { path: "/e2e-allowed/notes.txt", content: "nope" },
          },
        }),
      );
      await until(() => h.clientLines.length > linesBefore, "denied tools/call response", 15_000);
      assert.deepEqual(JSON.parse(h.clientLines[linesBefore]!), {
        jsonrpc: "2.0",
        id: 2,
        error: { code: -32000, message: DENY_MESSAGE },
      });
      // The write never reached the MCP server:
      assert.ok(!h.serverLog().some((l) => l.includes("write_file")));

      const deny = auditEvents().find(
        (e) => e.decision === "deny" && e.action === "write",
      );
      assert.ok(deny, "no deny audit event recorded for the blocked call");
      assert.equal(deny.event_type, "action_denied");
      assert.equal(deny.resource, "fs/e2e-allowed/notes.txt");
      assert.equal(deny.enforcing_principal, PEP_ID);
      assert.equal(deny.agent_id, "agent_local");
      assert.notEqual(deny.enforcing_principal, deny.agent_id);
    });
  },
);
