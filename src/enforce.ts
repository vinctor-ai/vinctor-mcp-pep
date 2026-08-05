import type { MappedCall } from "./mapper.js";
import { buildProof } from "./pop.js";

export const ENFORCE_TIMEOUT_MS = 5000;
export const ENFORCE_MAX_RESPONSE_BYTES = 64 * 1024;

/**
 * The ONLY client-facing deny text. Deliberately constant: no action/resource
 * interpolation, no grant existence, no service detail (the tested
 * no-disclosure invariant shared with the hooks — never reword it to include
 * classified context).
 */
export const DENY_MESSAGE = "Denied by Vinctor authorization (fail-closed).";

export type EnforceEnv = Record<string, string | undefined>;

function hasUsableAuditEventId(value: unknown): value is string {
  return typeof value === "string" && /[A-Za-z0-9]/.test(value);
}

/**
 * POST {VINCTOR_ENDPOINT}/v1/enforce/delegated and decide permit/deny.
 *
 * Returns true ONLY for a verifiable permit; never throws. D-8: a permit is
 * read from the response body (`decision === "permit"` AND a string
 * `audit_event_id` containing an ASCII alphanumeric) — a bare HTTP 200 is NOT a permit. Every other outcome
 * (missing env, network error, timeout, non-200, malformed body) is false,
 * which the proxy turns into a fail-closed deny.
 */
export async function isPermitted(
  call: MappedCall,
  env: EnforceEnv,
  fetchFn: typeof fetch = fetch,
  timeoutMs: number = ENFORCE_TIMEOUT_MS,
): Promise<boolean> {
  const endpoint = env["VINCTOR_ENDPOINT"];
  const pepKey = env["VINCTOR_PEP_KEY"];
  const grantRef = env["VINCTOR_GRANT_REF"];
  // The real delegated contract (vinctor-core v1_http._parse_delegated_enforce_body)
  // requires the asserted subject: exactly {workspace_id, agent_id, grant_ref,
  // action, resource} — missing OR extra fields are a 400.
  const workspaceId = env["VINCTOR_WORKSPACE_ID"];
  const agentId = env["VINCTOR_AGENT_ID"];
  if (!endpoint || !pepKey || !grantRef || !workspaceId || !agentId) return false;

  const url = endpoint.replace(/\/+$/, "") + "/v1/enforce/delegated";
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-PEP-Key": pepKey,
  };
  const boundaryId = env["VINCTOR_BOUNDARY_ID"];
  if (boundaryId) headers["X-Vinctor-Boundary-Id"] = boundaryId;
  const subjectToken = env["VINCTOR_SUBJECT_TOKEN"];
  if (subjectToken) headers["X-Subject-Token"] = subjectToken;
  // Proof-of-possession (ADR 0007 C3): ONLY when BOTH the pop secret and the
  // token id are configured, bind a fresh proof to the SAME (action, resource)
  // this request asserts. One var without the other sends NO proof header
  // (never a partial/malformed proof; the server decides on the bearer alone).
  const popSecret = env["VINCTOR_SUBJECT_TOKEN_POP_SECRET"];
  const tokenId = env["VINCTOR_SUBJECT_TOKEN_ID"];
  if (popSecret && tokenId) {
    headers["X-Subject-Token-Proof"] = buildProof(popSecret, tokenId, call.action, call.resource);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        workspace_id: workspaceId,
        agent_id: agentId,
        grant_ref: grantRef,
        action: call.action,
        resource: call.resource,
      }),
      signal: controller.signal,
    });
    if (res.status !== 200) {
      void res.body?.cancel().catch(() => undefined);
      return false;
    }
    const body = await readBoundedJson(res, controller.signal);
    if (body === null || typeof body !== "object" || Array.isArray(body)) return false;
    const b = body as { decision?: unknown; audit_event_id?: unknown };
    return (
      b.decision === "permit" &&
      hasUsableAuditEventId(b.audit_event_id)
    );
  } catch {
    return false; // unreachable / timeout / malformed response → fail closed
  } finally {
    clearTimeout(timer);
  }
}

async function readBoundedJson(response: Response, signal: AbortSignal): Promise<unknown> {
  if (response.body === null) throw new Error("missing response body");
  const reader = response.body.getReader();
  let onAbort = (): void => undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => {
      void reader.cancel().catch(() => undefined);
      reject(new Error("response body timed out"));
    };
    if (signal.aborted) {
      onAbort();
    } else {
      signal.addEventListener("abort", onAbort, { once: true });
    }
  });
  const bytes = new Uint8Array(ENFORCE_MAX_RESPONSE_BYTES);
  let offset = 0;
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), aborted]);
      if (done) break;
      if (offset + value.byteLength > ENFORCE_MAX_RESPONSE_BYTES) {
        void reader.cancel().catch(() => undefined);
        throw new Error("response body exceeds limit");
      }
      bytes.set(value, offset);
      offset += value.byteLength;
    }
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, offset)),
    ) as unknown;
  } finally {
    signal.removeEventListener("abort", onAbort);
    try {
      reader.releaseLock();
    } catch {
      // An abort may still be cancelling an outstanding read.
    }
  }
}
