import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import {
  isPermitted,
  DENY_MESSAGE,
  ENFORCE_MAX_RESPONSE_BYTES,
} from "../src/enforce.js";
import { popCanonical, popMac } from "../src/pop.js";
import type { MappedCall } from "../src/mapper.js";

const CALL: MappedCall = { action: "read", resource: "fs/home/u/notes.txt" };
const ENV = {
  VINCTOR_ENDPOINT: "https://vinctor.example",
  VINCTOR_PEP_KEY: "pep_test_key",
  VINCTOR_GRANT_REF: "grt_test_ref",
  VINCTOR_WORKSPACE_ID: "ws_test",
  VINCTOR_AGENT_ID: "agent_test",
};

type Captured = { url: string; init: RequestInit };

/** Stub fetch returning a fixed response; records the call. */
function stubFetch(
  status: number,
  body: string,
  captured: Captured[] = [],
): typeof fetch {
  return (async (url: unknown, init?: RequestInit): Promise<Response> => {
    captured.push({ url: String(url), init: init ?? {} });
    return new Response(body, { status, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
}

const PERMIT_BODY = JSON.stringify({ decision: "permit", audit_event_id: "evt_1" });

describe("isPermitted — D-8 body-verified permit", () => {
  it("200 with decision=permit and non-empty audit_event_id → true", async () => {
    const captured: Captured[] = [];
    assert.equal(await isPermitted(CALL, ENV, stubFetch(200, PERMIT_BODY, captured)), true);
    const req = captured[0]!;
    assert.equal(req.url, "https://vinctor.example/v1/enforce/delegated");
    assert.equal(req.init.method, "POST");
    const headers = req.init.headers as Record<string, string>;
    assert.equal(headers["X-PEP-Key"], "pep_test_key");
    assert.equal("X-Subject-Token" in headers, false); // absent unless configured
    const body = JSON.parse(String(req.init.body)) as Record<string, unknown>;
    // Exactly the real delegated contract's five fields — the service 400s on
    // missing AND on extra fields (vinctor-core _parse_delegated_enforce_body).
    assert.deepEqual(Object.keys(body).sort(), [
      "action",
      "agent_id",
      "grant_ref",
      "resource",
      "workspace_id",
    ]);
    assert.deepEqual(body, {
      workspace_id: "ws_test",
      agent_id: "agent_test",
      grant_ref: "grt_test_ref",
      action: "read",
      resource: CALL.resource,
    });
  });

  it("sends X-Subject-Token when VINCTOR_SUBJECT_TOKEN is set", async () => {
    const captured: Captured[] = [];
    const env = { ...ENV, VINCTOR_SUBJECT_TOKEN: "vat_subject" };
    assert.equal(await isPermitted(CALL, env, stubFetch(200, PERMIT_BODY, captured)), true);
    const headers = captured[0]!.init.headers as Record<string, string>;
    assert.equal(headers["X-Subject-Token"], "vat_subject");
  });

  it("sends the configured boundary identity to a default-closed service", async () => {
    const captured: Captured[] = [];
    const env = { ...ENV, VINCTOR_BOUNDARY_ID: "bnd_mcp_pep" };
    assert.equal(await isPermitted(CALL, env, stubFetch(200, PERMIT_BODY, captured)), true);
    const headers = captured[0]!.init.headers as Record<string, string>;
    assert.equal(headers["X-Vinctor-Boundary-Id"], "bnd_mcp_pep");
  });

  it("trailing slash on the endpoint does not double the path", async () => {
    const captured: Captured[] = [];
    const env = { ...ENV, VINCTOR_ENDPOINT: "https://vinctor.example/" };
    await isPermitted(CALL, env, stubFetch(200, PERMIT_BODY, captured));
    assert.equal(captured[0]!.url, "https://vinctor.example/v1/enforce/delegated");
  });

  it("bare 200 (empty JSON body) → false (a 200 is NOT a permit)", async () => {
    assert.equal(await isPermitted(CALL, ENV, stubFetch(200, "{}")), false);
  });

  it("200 with decision=permit but missing audit_event_id → false", async () => {
    assert.equal(
      await isPermitted(CALL, ENV, stubFetch(200, JSON.stringify({ decision: "permit" }))),
      false,
    );
  });

  it("200 with a whitespace-only audit_event_id → false (PKA-129)", async () => {
    // A blank id is no evidence: not a usable audit correlation, so it fails
    // closed like a missing one — the rule every Vinctor adapter enforces.
    for (const id of ["   ", "\t", "\n", "\u0085", "\uFEFF", "\u200B", "\u001C"]) {
      const body = JSON.stringify({ decision: "permit", audit_event_id: id });
      assert.equal(await isPermitted(CALL, ENV, stubFetch(200, body)), false, JSON.stringify(id));
    }
  });

  it("200 with empty-string audit_event_id → false", async () => {
    const body = JSON.stringify({ decision: "permit", audit_event_id: "" });
    assert.equal(await isPermitted(CALL, ENV, stubFetch(200, body)), false);
  });

  it("200 with decision=deny → false even with an audit_event_id", async () => {
    const body = JSON.stringify({ decision: "deny", audit_event_id: "evt_2" });
    assert.equal(await isPermitted(CALL, ENV, stubFetch(200, body)), false);
  });

  it("200 with a non-JSON body → false", async () => {
    assert.equal(await isPermitted(CALL, ENV, stubFetch(200, "OK")), false);
  });

  it("200 with a JSON array body → false", async () => {
    assert.equal(await isPermitted(CALL, ENV, stubFetch(200, "[]")), false);
  });

  it("403 deny → false", async () => {
    const body = JSON.stringify({ decision: "deny", error: "action_denied" });
    assert.equal(await isPermitted(CALL, ENV, stubFetch(403, body)), false);
  });

  it("5xx → false", async () => {
    assert.equal(await isPermitted(CALL, ENV, stubFetch(503, "{}")), false);
  });

  it("network error → false (never throws)", async () => {
    const failing = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    assert.equal(await isPermitted(CALL, ENV, failing), false);
  });

  it("timeout aborts and → false", async () => {
    const hanging = ((url: unknown, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      })) as typeof fetch;
    assert.equal(await isPermitted(CALL, ENV, hanging, 20), false);
  });

  it("keeps the timeout active while reading the response body", async () => {
    const stalledBody = new ReadableStream<Uint8Array>({
      start: () => {},
    });
    const fetchFn = (async () => new Response(stalledBody, { status: 200 })) as typeof fetch;

    const result = await Promise.race([
      isPermitted(CALL, ENV, fetchFn, 20),
      new Promise<"timed_out">((resolve) => setTimeout(() => resolve("timed_out"), 100)),
    ]);
    assert.equal(result, false);
  });

  it("rejects a permit response whose body exceeds the byte ceiling", async () => {
    const padding = "x".repeat(ENFORCE_MAX_RESPONSE_BYTES);
    const body = JSON.stringify({
      decision: "permit",
      audit_event_id: "evt_large",
      padding,
    });

    assert.equal(await isPermitted(CALL, ENV, stubFetch(200, body)), false);
  });

  for (const missing of [
    "VINCTOR_ENDPOINT",
    "VINCTOR_PEP_KEY",
    "VINCTOR_GRANT_REF",
    "VINCTOR_WORKSPACE_ID",
    "VINCTOR_AGENT_ID",
  ] as const) {
    it(`missing ${missing} → false without any HTTP request`, async () => {
      const captured: Captured[] = [];
      const env = { ...ENV, [missing]: undefined };
      assert.equal(await isPermitted(CALL, env, stubFetch(200, PERMIT_BODY, captured)), false);
      assert.equal(captured.length, 0);
    });
  }
});

describe("isPermitted — X-Subject-Token-Proof (PoP)", () => {
  const POP_ENV = {
    ...ENV,
    VINCTOR_SUBJECT_TOKEN: "vat_subject",
    VINCTOR_SUBJECT_TOKEN_POP_SECRET: "pop_secret_test",
    VINCTOR_SUBJECT_TOKEN_ID: "vtk_test_id",
  };

  it("with BOTH pop env vars: sends a well-formed proof bound to THIS call", async () => {
    const captured: Captured[] = [];
    const before = Math.floor(Date.now() / 1000);
    assert.equal(await isPermitted(CALL, POP_ENV, stubFetch(200, PERMIT_BODY, captured)), true);
    const after = Math.floor(Date.now() / 1000);
    const headers = captured[0]!.init.headers as Record<string, string>;
    assert.equal(headers["X-Subject-Token"], "vat_subject"); // still the bearer token
    const proof = headers["X-Subject-Token-Proof"];
    assert.ok(proof, "proof header missing");
    const parts = proof.split(".");
    assert.equal(parts.length, 3);
    const [tsRaw, nonce, mac] = parts as [string, string, string];
    const ts = Number(tsRaw);
    assert.ok(Number.isInteger(ts) && ts >= before && ts <= after, `stale ts: ${tsRaw}`);
    assert.ok(nonce.length > 0);
    // The mac verifies against the SAME (action, resource) sent in the enforce
    // body, the configured token id, and the pop secret — i.e. what the
    // server's verify_pop recomputes.
    const body = JSON.parse(String(captured[0]!.init.body)) as { action: string; resource: string };
    assert.equal(
      mac,
      popMac(
        "pop_secret_test",
        popCanonical(body.action, body.resource, ts, nonce, "vtk_test_id"),
      ),
    );
    assert.deepEqual({ action: body.action, resource: body.resource }, CALL);
  });

  it("uses a fresh nonce per request (two calls → two different proofs)", async () => {
    const captured: Captured[] = [];
    const fetchFn = stubFetch(200, PERMIT_BODY, captured);
    await isPermitted(CALL, POP_ENV, fetchFn);
    await isPermitted(CALL, POP_ENV, fetchFn);
    const proofOf = (i: number) =>
      (captured[i]!.init.headers as Record<string, string>)["X-Subject-Token-Proof"]!;
    assert.notEqual(proofOf(0).split(".")[1], proofOf(1).split(".")[1]);
  });

  it("secret WITHOUT token id → no proof header (never a partial proof)", async () => {
    const captured: Captured[] = [];
    const env = { ...POP_ENV, VINCTOR_SUBJECT_TOKEN_ID: undefined };
    assert.equal(await isPermitted(CALL, env, stubFetch(200, PERMIT_BODY, captured)), true);
    const headers = captured[0]!.init.headers as Record<string, string>;
    assert.equal("X-Subject-Token-Proof" in headers, false);
  });

  it("token id WITHOUT secret → no proof header (never a partial proof)", async () => {
    const captured: Captured[] = [];
    const env = { ...POP_ENV, VINCTOR_SUBJECT_TOKEN_POP_SECRET: undefined };
    assert.equal(await isPermitted(CALL, env, stubFetch(200, PERMIT_BODY, captured)), true);
    const headers = captured[0]!.init.headers as Record<string, string>;
    assert.equal("X-Subject-Token-Proof" in headers, false);
  });

  it("no pop env at all → request unchanged (no proof header)", async () => {
    const captured: Captured[] = [];
    const env = { ...ENV, VINCTOR_SUBJECT_TOKEN: "vat_subject" };
    assert.equal(await isPermitted(CALL, env, stubFetch(200, PERMIT_BODY, captured)), true);
    const headers = captured[0]!.init.headers as Record<string, string>;
    assert.equal("X-Subject-Token-Proof" in headers, false);
  });
});

describe("DENY_MESSAGE no-disclosure contract", () => {
  it("is the exact constant with no interpolation slots", () => {
    assert.equal(DENY_MESSAGE, "Denied by Vinctor authorization (fail-closed).");
  });
});
