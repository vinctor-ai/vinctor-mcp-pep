import { describe, it, before, after } from "node:test";
import { strict as assert } from "node:assert";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startCliHarness, until, type CliHarness } from "../test/helpers.js";
import { DENY_MESSAGE } from "../src/enforce.js";
import { buildProof } from "../src/pop.js";

/**
 * REAL-service e2e for proof-of-possession (npm run test:e2e): boots a
 * throwaway Vinctor service from an explicitly selected pinned checkout,
 * mints a --pop subject token, enables the require-pop mandate, and asserts:
 *  1. the proxy WITH the pop env pair forwards a permitted tools/call — the
 *     TS-generated X-Subject-Token-Proof is accepted by the REAL verify_pop;
 *  2. a REPLAYED proof (same ts.nonce.mac POSTed twice, forced via a direct
 *     /v1/enforce/delegated call) is rejected the second time;
 *  3. the proxy WITHOUT the pop env (bearer-only, same pop token) is denied —
 *     the mandate actually bites, so (1) passed BECAUSE of the proof.
 */

const CORE_DIR = process.env["VINCTOR_CORE_DIR"];
if (!CORE_DIR) {
  throw new Error("PoP real-service e2e requires VINCTOR_CORE_DIR");
}
const VINCTOR_BIN = join(CORE_DIR, ".venv", "bin", "vinctor");

const PEP_ID = "pep_mcp_proxy_pop_e2e";
const ALLOWED_SCOPE = "read:fs/e2e-pop/*";
const PEP_PROVISION_VERB = process.env["VINCTOR_E2E_PEP_PROVISION_VERB"] ?? "create";

if (PEP_PROVISION_VERB !== "create" && PEP_PROVISION_VERB !== "rotate") {
  throw new Error("VINCTOR_E2E_PEP_PROVISION_VERB must be create or rotate");
}

if (!existsSync(VINCTOR_BIN)) {
  throw new Error(
    `PoP real-service e2e requires an executable vinctor-core venv at ${VINCTOR_BIN}; ` +
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
  "proof-of-possession against the REAL vinctor service (require_pop on)",
  () => {
    let service: ChildProcess;
    let serviceOut = "";
    let dbPath = "";
    let endpoint = "";
    let boundaryId = "";
    let grantRef = "";
    let pepKey = "";
    let subjectToken = "";
    let tokenId = "";
    let popSecret = "";
    let hPop: CliHarness; // proxy WITH the pop env pair
    let hBearer: CliHarness; // proxy WITHOUT it (control)

    before(async () => {
      const dir = mkdtempSync(join(tmpdir(), "vinctor-mcp-pep-pop-e2e-"));
      dbPath = join(dir, "vinctor.db");
      const port = await freePort();

      // 1. Boot the throwaway service.
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
      const agentKey = exports.get("VINCTOR_AGENT_KEY") ?? "";
      grantRef = exports.get("VINCTOR_GRANT_REF") ?? "";
      assert.ok(endpoint && boundaryId && agentKey && grantRef, `missing exports in:\n${serviceOut}`);

      // 2. Provision the PEP key.
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

      // 3. Mint a --pop subject token: capture token, token_id AND pop_secret.
      const minted = vinctorSync(
        ["--endpoint", endpoint, "--agent-key", agentKey, "agent", "token", "mint",
          "--grant-ref", grantRef, "--audience", PEP_ID, "--pop", "-o", "json"],
        "pop subject token mint",
      );
      subjectToken = String(minted["token"] ?? "");
      tokenId = String(minted["token_id"] ?? "");
      popSecret = String(minted["pop_secret"] ?? "");
      assert.ok(subjectToken.length > 0, `mint returned no token: ${JSON.stringify(minted)}`);
      assert.ok(tokenId.startsWith("vtk_"), `mint returned no vtk_ token_id: ${tokenId}`);
      assert.ok(popSecret.length > 0, `mint returned no pop_secret: ${JSON.stringify(minted)}`);

      // 4. Harden: require-pop mandate for the (default) subject agent_local.
      const mandated = vinctorSync(
        ["--db", dbPath, "operator", "require-pop", "enable", "-o", "json"],
        "require-pop enable",
      );
      assert.equal(mandated["require_pop"], true);

      // 5. Two proxies against the REAL service: with and without the pop env.
      const baseEnv = {
        VINCTOR_ENDPOINT: endpoint,
        VINCTOR_PEP_KEY: pepKey,
        VINCTOR_GRANT_REF: grantRef,
        VINCTOR_WORKSPACE_ID: "ws_local",
        VINCTOR_AGENT_ID: "agent_local",
        VINCTOR_BOUNDARY_ID: boundaryId,
        VINCTOR_SUBJECT_TOKEN: subjectToken,
      };
      hPop = startCliHarness({
        ...baseEnv,
        VINCTOR_SUBJECT_TOKEN_POP_SECRET: popSecret,
        VINCTOR_SUBJECT_TOKEN_ID: tokenId,
      });
      hBearer = startCliHarness(baseEnv);
    });

    after(async () => {
      if (hPop) await hPop.stop();
      if (hBearer) await hBearer.stop();
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

    it("proxy WITH the pop env: permitted tools/call FORWARDS (proof accepted)", async () => {
      const raw = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "read_text_file", arguments: { path: "/e2e-pop/notes.txt" } },
      });
      hPop.send(raw);
      await until(() => hPop.clientLines.length >= 1, "pop-proven tools/call response", 15_000);
      const res = JSON.parse(hPop.clientLines[0]!) as { id: number; result?: { echoRaw: string } };
      assert.equal(res.id, 1);
      assert.equal(res.result?.echoRaw, raw, `expected forward, got: ${hPop.clientLines[0]}`);

      const permit = auditEvents().find(
        (e) => e.decision === "permit" && e.resource === "fs/e2e-pop/notes.txt",
      );
      assert.ok(permit, "no permit audit event recorded for the pop-proven call");
      assert.equal(permit.event_type, "action_permitted");
      assert.equal(permit.subject_token_verified, true);
      assert.equal(permit.token_id, tokenId); // the decision is about OUR pop token
    });

    it("a REPLAYED proof is rejected (same ts.nonce.mac twice → 403 the second time)", async () => {
      // The proxy always generates a fresh nonce, so force the replay with a
      // direct POST: ONE fixed proof, sent twice. The first acceptance is an
      // independent live check that the REAL Python verify_pop accepts a mac
      // computed by OUR TS implementation for this exact (action, resource).
      const action = "read";
      const resource = "fs/e2e-pop/direct.txt";
      const proof = buildProof(popSecret, tokenId, action, resource);
      const post = async (): Promise<Response> =>
        await fetch(endpoint.replace(/\/+$/, "") + "/v1/enforce/delegated", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-PEP-Key": pepKey,
            "X-Vinctor-Boundary-Id": boundaryId,
            "X-Subject-Token": subjectToken,
            "X-Subject-Token-Proof": proof,
          },
          body: JSON.stringify({
            workspace_id: "ws_local",
            agent_id: "agent_local",
            grant_ref: grantRef,
            action,
            resource,
          }),
        });

      const first = await post();
      const firstText = await first.text();
      assert.equal(first.status, 200, `fresh TS proof rejected: ${firstText}`);
      const firstBody = JSON.parse(firstText) as { decision?: string; audit_event_id?: string };
      assert.equal(firstBody.decision, "permit");
      assert.ok(firstBody.audit_event_id, "permit without audit_event_id");

      const second = await post();
      assert.equal(second.status, 403, "replayed proof was NOT rejected");
    });

    it("proxy WITHOUT the pop env: same call is DENIED under require_pop (control)", async () => {
      const marker = "/e2e-pop/bearer-control.txt";
      hBearer.send(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "read_text_file", arguments: { path: marker } },
        }),
      );
      await until(() => hBearer.clientLines.length >= 1, "bearer-only response", 15_000);
      assert.deepEqual(JSON.parse(hBearer.clientLines[0]!), {
        jsonrpc: "2.0",
        id: 2,
        error: { code: -32000, message: DENY_MESSAGE },
      });
      // The call never reached the MCP server:
      assert.ok(!hBearer.serverLog().some((l) => l.includes(marker)));
    });
  },
);
