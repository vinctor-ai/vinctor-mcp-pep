import type { ChildProcessWithoutNullStreams } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { decodeUtf8Strict, hasDuplicateObjectKeys } from "./json.js";
import { LineSplitter } from "./lines.js";
import { mapToolCall, isParseUnsafe, type MappedCall } from "./mapper.js";
import { decideMethod } from "./methods.js";
import { isPermitted, DENY_MESSAGE, ENFORCE_TIMEOUT_MS } from "./enforce.js";
import { createBlockedUnmappedObserver } from "./observe.js";
import type { UnmappedVerdict } from "./config.js";
import {
  asRecord,
  hasValidEnforcedParams,
  hasValidEnvelope,
  hasValidPassParams,
  requestIdOf,
  type JsonRpcId,
} from "./protocol.js";
import { pumpLines, spawnTransport, writeBufferedLine, writeLine } from "./stdio.js";

export type ProxyOptions = {
  /** Real MCP server command (argv[0]) and its arguments. */
  command: string;
  args: string[];
  /** Client-facing streams (process.stdin/stdout/stderr in production). */
  clientIn: Readable;
  clientOut: Writable;
  clientErr: Writable;
  /** Environment the proxy reads Vinctor configuration from. */
  env: Record<string, string | undefined>;
  /** Injectable for tests; defaults to global fetch. */
  fetchFn?: typeof fetch;
  /** Enforce round-trip timeout; defaults to ENFORCE_TIMEOUT_MS (5s). */
  enforceTimeoutMs?: number;
  /** Maximum bytes in one newline-framed MCP message; defaults to 8 MiB. */
  maxLineBytes?: number;
  /**
   * Verdict for tools/call the mapper cannot map. Default "deny" (fail-closed).
   * "allow" forwards unmapped calls WITHOUT enforcement — an explicit operator
   * opt-out (--config) that weakens the non-bypassability guarantee.
   */
  unmappedVerdict?: UnmappedVerdict;
};

export type RunningProxy = {
  child: ChildProcessWithoutNullStreams;
  /** Resolves with the proxy's exit code once the server process ends. */
  done: Promise<number>;
};

/**
 * Start the stdio proxy: spawn the real MCP server, relay traffic, and gate
 * every client → server JSON-RPC request through Vinctor delegated
 * enforcement. Dispatch is fail-closed by enumeration (PKA-100, methods.ts):
 * tools/call has its tool-mapping gate; enumerated lifecycle methods pass;
 * data-reaching methods (resources/*, prompts/*, completion/complete) are
 * enforced; unknown methods, batches, and unclassifiable lines are denied or
 * dropped — never silently forwarded.
 *
 * Invariants (see AGENTS.md):
 * - Fail closed: no error path forwards an unauthorized request.
 * - No disclosure: the deny error is the constant DENY_MESSAGE, nothing else.
 * - Transparent proxy for enumerated pass-through traffic and server → client
 *   output within the shared message ceiling: forwarded lines are
 *   byte-faithful, while oversized or parser-ambiguous lines are dropped whole.
 */
export function startProxy(opts: ProxyOptions): RunningProxy {
  const fetchFn = opts.fetchFn ?? fetch;
  const enforceTimeoutMs = opts.enforceTimeoutMs ?? ENFORCE_TIMEOUT_MS;
  const unmappedVerdict: UnmappedVerdict = opts.unmappedVerdict ?? "deny";
  const { child, serverRequests, diagnostic } = spawnTransport({
    command: opts.command,
    args: opts.args,
    env: opts.env,
    clientOut: opts.clientOut,
    clientErr: opts.clientErr,
    maxLineBytes: opts.maxLineBytes,
  });
  const observeBlockedUnmapped = createBlockedUnmappedObserver(
    opts.env,
    fetchFn,
    undefined,
    (dropped) => {
      diagnostic(
        `vinctor-mcp-pep: dropped blocked-unmapped observation (queue full; dropped=${dropped})`,
      );
    },
  );

  const forwardReservedToServer = async (
    raw: Buffer,
    msg: Record<string, unknown>,
  ): Promise<void> => {
    if (!("id" in msg)) {
      await writeBufferedLine(child.stdin, raw);
      return;
    }
    try {
      await writeLine(child.stdin, raw);
    } catch (error) {
      serverRequests.releaseClientRequest(msg);
      throw error;
    }
    if (!serverRequests.markClientRequestForwarded(msg)) {
      serverRequests.releaseClientRequest(msg);
      await rejectMalformed(msg);
    }
  };

  const forwardToServer = async (
    raw: Buffer,
    msg?: Record<string, unknown>,
  ): Promise<void> => {
    if (msg === undefined) {
      await writeBufferedLine(child.stdin, raw);
      return;
    }
    if (!serverRequests.reserveClientRequest(msg)) {
      await rejectMalformed(msg);
      return;
    }
    await forwardReservedToServer(raw, msg);
  };

  const denyToClient = async (id: JsonRpcId): Promise<void> => {
    const error = {
      jsonrpc: "2.0" as const,
      id,
      error: { code: -32000, message: DENY_MESSAGE },
    };
    await writeBufferedLine(opts.clientOut, Buffer.from(JSON.stringify(error), "utf8"));
  };

  const rejectMalformed = async (msg: Record<string, unknown>): Promise<void> => {
    if ("method" in msg && "id" in msg) await denyToClient(requestIdOf(msg));
    else diagnostic("vinctor-mcp-pep: dropped malformed client message (fail-closed)");
  };

  /** Forward only when EVERY (action, resource) check comes back a permit. */
  const gateChecks = async (raw: Buffer, msg: Record<string, unknown>, id: JsonRpcId, checks: readonly MappedCall[]): Promise<void> => {
    if (!serverRequests.reserveClientRequest(msg)) {
      await rejectMalformed(msg);
      return;
    }
    for (const check of checks) {
      if (!(await isPermitted(check, opts.env, fetchFn, enforceTimeoutMs))) {
        serverRequests.releaseClientRequest(msg);
        await denyToClient(id);
        return;
      }
    }
    await forwardReservedToServer(raw, msg);
  };

  /**
   * A tools/call the tool mapper cannot map ⇒ fail-closed deny WITHOUT calling
   * the enforce service (best-effort observed for the audit trail), unless the
   * operator explicitly opted out with unmapped_verdict "allow". Unknown
   * JSON-RPC methods never use this compatibility escape hatch.
   */
  const handleUnmapped = async (raw: Buffer, msg: Record<string, unknown>, id: JsonRpcId, name: string | null, respond: boolean): Promise<void> => {
    if (unmappedVerdict === "allow") {
      await forwardToServer(raw, msg);
      return;
    }
    if (name !== null) observeBlockedUnmapped(name);
    if (respond) await denyToClient(id);
    else diagnostic("vinctor-mcp-pep: dropped unmapped notification (fail-closed)");
  };

  const handleUnknownMethod = async (
    id: JsonRpcId,
    method: string,
    respond: boolean,
  ): Promise<void> => {
    observeBlockedUnmapped(method);
    if (respond) await denyToClient(id);
    else diagnostic("vinctor-mcp-pep: dropped unmapped notification (fail-closed)");
  };

  const gateToolsCall = async (raw: Buffer, msg: Record<string, unknown>): Promise<void> => {
    const id = requestIdOf(msg);
    const params = asRecord(msg["params"]);
    const name = params?.["name"];
    const argumentValue = params?.["arguments"];
    if (
      params === null ||
      typeof name !== "string" ||
      name.length === 0 ||
      ("arguments" in params && asRecord(argumentValue) === null)
    ) {
      await rejectMalformed(msg);
      return;
    }
    const args = asRecord(argumentValue) ?? {};
    const mapped = mapToolCall(name, args);
    // PKA-159: a RECOGNISED tool whose argument cannot be expressed is a hard
    // deny, and the operator's `unmapped_verdict: "allow"` does NOT reach it.
    // That escape hatch exists for tools this proxy does not know; here the
    // tool is known and the target is not nameable, so forwarding would run a
    // call the PDP was never asked about. Still observed, so the refusal is
    // auditable rather than silent — before this, adding one `/./` to a path
    // turned a gated secret read into an untraced pass-through.
    if (isParseUnsafe(mapped)) {
      observeBlockedUnmapped(name);
      await denyToClient(id);
      return;
    }
    if (mapped === null || mapped === undefined) {
      await handleUnmapped(raw, msg, id, name, true);
      return;
    }
    await gateChecks(raw, msg, id, [mapped, ...(mapped.alsoRequires ?? [])]);
  };

  const handleLine = async (raw: Buffer): Promise<void> => {
    let msg: unknown;
    const text = decodeUtf8Strict(raw);
    if (text === null) {
      diagnostic("vinctor-mcp-pep: dropped non-JSON client line (fail-closed)");
      return;
    }
    try {
      msg = JSON.parse(text);
    } catch {
      // Not JSON to US — fail closed and DROP. Forwarding would trust the
      // server's parser to agree with ours: a lenient downstream parser
      // (JSON5-ish quotes, BOM tolerance) could read a tools/call out of a
      // line we couldn't gate. Spec-compliant clients never send non-JSON.
      diagnostic("vinctor-mcp-pep: dropped non-JSON client line (fail-closed)");
      return;
    }
    if (hasDuplicateObjectKeys(text)) {
      await denyToClient(null);
      return;
    }
    if (Array.isArray(msg)) {
      // A JSON-RPC batch: MCP stdio does not use batches, and one could
      // smuggle ANY request past a per-message gate. Fail closed.
      await denyToClient(null);
      return;
    }
    if (msg === null || typeof msg !== "object") {
      // A JSON scalar is not a JSON-RPC message; nothing to classify.
      diagnostic("vinctor-mcp-pep: dropped non-message client line (fail-closed)");
      return;
    }
    const m = msg as Record<string, unknown>;
    if (!hasValidEnvelope(m)) {
      await rejectMalformed(m);
      return;
    }
    const method = m["method"];
    if (typeof method !== "string") {
      // No method: forward ONLY a response-shaped message (the client's
      // reply to a server-initiated sampling/roots request — blocking those
      // would deadlock the protocol). Anything else is unclassifiable.
      if (!("method" in m) && serverRequests.consumeResponse(m)) await forwardToServer(raw);
      else await rejectMalformed(m);
      return;
    }
    const decision = decideMethod(method, m["params"]);
    if (
      decision.verdict !== "unknown" &&
      (("id" in m ? "request" : "notification") !== decision.kind ||
        (decision.verdict === "pass" && !hasValidPassParams(method, m["params"])) ||
        (decision.verdict === "enforce" && !hasValidEnforcedParams(method, m["params"])))
    ) {
      await rejectMalformed(m);
      return;
    }
    const passParams = asRecord(m["params"]);
    if (
      (method === "notifications/cancelled" &&
        !serverRequests.canCancelRequest(passParams?.["requestId"])) ||
      (method === "notifications/progress" &&
        !serverRequests.canReportProgress(passParams?.["progressToken"]))
    ) {
      await rejectMalformed(m);
      return;
    }
    switch (decision.verdict) {
      case "pass":
        await forwardToServer(raw, m);
        return;
      case "gate-tools-call":
        await gateToolsCall(raw, m);
        return;
      case "enforce":
        await gateChecks(raw, m, requestIdOf(m), decision.checks);
        return;
      case "unknown":
        await handleUnknownMethod(requestIdOf(m), method, "id" in m);
        return;
    }
  };

  const splitter = new LineSplitter({
    maxLineBytes: opts.maxLineBytes,
    onOversize: () => {
      diagnostic("vinctor-mcp-pep: dropped oversized client line (fail-closed)");
    },
  });
  void pumpLines(opts.clientIn, splitter, handleLine).then(
    () => child.stdin.end(),
    () => child.stdin.end(),
  );

  const done = new Promise<number>((resolve) => {
    child.on("error", (err) => {
      diagnostic(`vinctor-mcp-pep: failed to start server command: ${err.message}`);
      resolve(1);
    });
    child.on("close", (code) => resolve(code ?? 1));
  });

  return { child, done };
}
