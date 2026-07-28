export const OBSERVE_TIMEOUT_MS = 500;
export const MAX_CONCURRENT_OBSERVATIONS = 8;
export const MAX_QUEUED_OBSERVATIONS = 256;
export const MAX_OBSERVED_TOOL_NAME_CHARS = 256;

export type ObserveEnv = Record<string, string | undefined>;
export type BlockedUnmappedObserver = (toolName: string) => void;
/** Reports one dropped observation and the running total dropped so far. */
export type ObservationDropReporter = (dropped: number) => void;

export function createBlockedUnmappedObserver(
  env: ObserveEnv,
  fetchFn: typeof fetch = fetch,
  timeoutMs: number = OBSERVE_TIMEOUT_MS,
  onDropped: ObservationDropReporter = () => undefined,
): BlockedUnmappedObserver {
  let inFlight = 0;
  let dropped = 0;
  const queued: string[] = [];
  const drain = (): void => {
    while (inFlight < MAX_CONCURRENT_OBSERVATIONS && queued.length > 0) {
      const toolName = queued.shift()!;
      inFlight += 1;
      void observeBlockedUnmapped(toolName, env, fetchFn, timeoutMs).finally(() => {
        inFlight -= 1;
        drain();
      });
    }
  };
  return (toolName): void => {
    // Overflow drops the NEWEST, not the oldest. Every unmapped call is
    // locally denied without a PDP round-trip, so an agent can emit them far
    // faster than they can be POSTed; evicting the oldest would let a burst of
    // cheap decoys push out an earlier sensitive observation — attacker-
    // selected loss of exactly the record that matters. Dropping the newest
    // still loses observations under sustained overflow, but which ones is no
    // longer the caller's choice. Never silent: every drop is reported with a
    // running total, like every other fail-closed drop path (PKA-131).
    if (queued.length >= MAX_QUEUED_OBSERVATIONS) {
      dropped += 1;
      onDropped(dropped);
      return;
    }
    queued.push(toolName.slice(0, MAX_OBSERVED_TOOL_NAME_CHARS));
    drain();
  };
}

/**
 * Best-effort audit for a locally blocked unmapped tool. This function never
 * throws, and callers do not await it, so observation health cannot affect the
 * fail-closed local verdict.
 */
export async function observeBlockedUnmapped(
  toolName: string,
  env: ObserveEnv,
  fetchFn: typeof fetch = fetch,
  timeoutMs: number = OBSERVE_TIMEOUT_MS,
): Promise<void> {
  const endpoint = env["VINCTOR_ENDPOINT"];
  const pepKey = env["VINCTOR_PEP_KEY"];
  const workspaceId = env["VINCTOR_WORKSPACE_ID"];
  const agentId = env["VINCTOR_AGENT_ID"];
  if (!endpoint || !pepKey || !workspaceId || !agentId) return;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-PEP-Key": pepKey,
  };
  const subjectToken = env["VINCTOR_SUBJECT_TOKEN"];
  if (subjectToken) headers["X-Subject-Token"] = subjectToken;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchFn(endpoint.replace(/\/+$/, "") + "/v1/observe", {
      method: "POST",
      headers,
      body: JSON.stringify({
        workspace_id: workspaceId,
        agent_id: agentId,
        classification: "unmapped",
        outcome: "blocked_unmapped",
        tool_name: toolName.slice(0, MAX_OBSERVED_TOOL_NAME_CHARS),
      }),
      signal: controller.signal,
    });
    await cancelUnusedBody(response.body, controller.signal);
  } catch {
    // Observation failures are an audit gap, never a reason to alter or delay
    // the local fail-closed deny.
  } finally {
    clearTimeout(timer);
  }
}

async function cancelUnusedBody(
  body: ReadableStream<Uint8Array> | null,
  signal: AbortSignal,
): Promise<void> {
  if (body === null) return;
  let onAbort = (): void => undefined;
  const aborted = new Promise<void>((resolve) => {
    onAbort = resolve;
    if (signal.aborted) {
      resolve();
    } else {
      signal.addEventListener("abort", onAbort, { once: true });
    }
  });
  try {
    await Promise.race([body.cancel().catch(() => undefined), aborted]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}
