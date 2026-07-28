import { Transform } from "node:stream";
import { decodeUtf8Strict, hasDuplicateObjectKeys } from "./json.js";
import { LineSplitter } from "./lines.js";
import {
  asRecord,
  hasValidEnvelope,
  isProgressToken,
  isProtocolId,
  isResponseShaped,
  requestIdOf,
  type JsonRpcId,
} from "./protocol.js";

export type ServerRequestTracker = {
  readonly observer: Transform;
  reserveClientRequest(message: Record<string, unknown>): boolean;
  markClientRequestForwarded(message: Record<string, unknown>): boolean;
  releaseClientRequest(message: Record<string, unknown>): void;
  canCancelRequest(id: unknown): boolean;
  canReportProgress(token: unknown): boolean;
  consumeResponse(message: Record<string, unknown>): boolean;
};

type TrackerOptions = {
  readonly maxPending?: number;
  readonly pendingTtlMs?: number;
  readonly maxLineBytes?: number;
  readonly maxKeyBytes?: number;
  readonly maxPendingBytes?: number;
  readonly onAmbiguous?: () => void;
  readonly onOversize?: () => void;
  readonly onUntrackable?: () => void;
  readonly now?: () => number;
};

export function createServerRequestTracker(options: TrackerOptions = {}): ServerRequestTracker {
  const maxPending = options.maxPending ?? 1024;
  const pendingTtlMs = options.pendingTtlMs ?? 300_000;
  const maxKeyBytes = options.maxKeyBytes ?? 4096;
  const maxPendingBytes = options.maxPendingBytes ?? 1024 * 1024;
  const now = options.now ?? Date.now;
  const pendingServer = new Map<
    string,
    { readonly observedAt: number; readonly progressKey?: string; readonly retainedBytes: number }
  >();
  const pendingClient = new Map<
    string,
    {
      readonly method: string;
      readonly progressKey?: string;
      readonly retainedBytes: number;
      forwarded: boolean;
    }
  >();
  const activeProgress = new Map<string, string>();
  const activeClientProgress = new Map<string, string>();
  const key = (value: string | number): string => `${typeof value}:${String(value)}`;
  const keyBytes = (value: string): number => Buffer.byteLength(value, "utf8");
  let retainedBytes = 0;
  const deleteServerRequest = (requestKey: string): boolean => {
    const request = pendingServer.get(requestKey);
    if (request === undefined) return false;
    pendingServer.delete(requestKey);
    retainedBytes -= request.retainedBytes;
    if (request.progressKey !== undefined && activeProgress.get(request.progressKey) === requestKey) {
      activeProgress.delete(request.progressKey);
    }
    return true;
  };
  const deleteClientRequest = (requestKey: string): boolean => {
    const request = pendingClient.get(requestKey);
    if (request === undefined) return false;
    pendingClient.delete(requestKey);
    retainedBytes -= request.retainedBytes;
    if (
      request.progressKey !== undefined &&
      activeClientProgress.get(request.progressKey) === requestKey
    ) {
      activeClientProgress.delete(request.progressKey);
    }
    return true;
  };
  /**
   * TTL eviction applies to SERVER-initiated requests only. Those ids and
   * progress tokens are attacker-controllable state the server can create
   * without bound, so reclaiming them matters.
   *
   * Client requests are exempt: a tools/call can legitimately outlive any
   * fixed TTL (a build, a test run), and evicting one does not end it — it
   * only makes the server's eventual response untrackable, so the response is
   * dropped and the client waits forever with no error, and a cancellation
   * for it stops being forwardable. Client entries are already bounded at
   * reservation time (maxPending / maxPendingBytes) and are released when the
   * response arrives or when the proxy denies before forwarding.
   */
  const prune = (current: number): void => {
    for (const [requestKey, request] of pendingServer) {
      if (current - request.observedAt > pendingTtlMs) deleteServerRequest(requestKey);
    }
  };
  const record = (text: string): boolean => {
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      return false;
    }
    const message = asRecord(value);
    if (message === null || !hasValidEnvelope(message)) return false;
    const id = requestIdOf(message);
    if (id === null) return !("id" in message) && typeof message["method"] === "string";
    const current = now();
    prune(current);
    const requestKey = key(id);
    if (typeof message["method"] === "string" && "id" in message) {
      if (pendingServer.has(requestKey) || pendingServer.size >= maxPending) return false;
      const requestBytes = keyBytes(requestKey);
      if (requestBytes > maxKeyBytes) return false;
      const progressToken = asRecord(asRecord(message["params"])?.["_meta"])?.["progressToken"];
      const progressKey = isProgressToken(progressToken) ? key(progressToken) : undefined;
      if (
        progressKey !== undefined &&
        (keyBytes(progressKey) > maxKeyBytes || activeProgress.has(progressKey))
      ) {
        return false;
      }
      const trackedProgressKey = progressKey;
      const entryBytes =
        requestBytes + (trackedProgressKey === undefined ? 0 : keyBytes(trackedProgressKey));
      if (retainedBytes + entryBytes > maxPendingBytes) return false;
      pendingServer.set(requestKey, {
        observedAt: current,
        progressKey: trackedProgressKey,
        retainedBytes: entryBytes,
      });
      retainedBytes += entryBytes;
      if (trackedProgressKey !== undefined) activeProgress.set(trackedProgressKey, requestKey);
    } else if (isResponseShaped(message)) {
      const clientRequest = pendingClient.get(requestKey);
      return clientRequest?.forwarded === true && deleteClientRequest(requestKey);
    } else {
      return false;
    }
    return true;
  };

  const splitter = new LineSplitter({
    maxLineBytes: options.maxLineBytes,
    onOversize: options.onOversize,
  });
  const newline = Buffer.from("\n");
  const observer = new Transform({
    transform(chunk: Buffer, _encoding, callback): void {
      for (const line of splitter.push(chunk)) {
        const text = decodeUtf8Strict(line);
        if (text === null || hasDuplicateObjectKeys(text)) {
          options.onAmbiguous?.();
          continue;
        }
        if (!record(text)) {
          options.onUntrackable?.();
          continue;
        }
        this.push(line);
        this.push(newline);
      }
      callback();
    },
    flush(callback): void {
      const rest = splitter.flush();
      if (rest !== null) {
        const text = decodeUtf8Strict(rest);
        if (text === null || hasDuplicateObjectKeys(text)) {
          options.onAmbiguous?.();
        } else {
          if (record(text)) this.push(rest);
          else options.onUntrackable?.();
        }
      }
      callback();
    },
  });
  observer.once("close", () => {
    pendingServer.clear();
    pendingClient.clear();
    activeProgress.clear();
    activeClientProgress.clear();
    retainedBytes = 0;
  });

  return {
    observer,
    reserveClientRequest(message): boolean {
      if (!("id" in message)) return true;
      const id = requestIdOf(message);
      const method = message["method"];
      if (id === null || typeof method !== "string") return false;
      const current = now();
      prune(current);
      const requestKey = key(id);
      const requestBytes = keyBytes(requestKey);
      const progressToken = asRecord(asRecord(message["params"])?.["_meta"])?.["progressToken"];
      const progressKey = isProgressToken(progressToken) ? key(progressToken) : undefined;
      const retainedRequestBytes =
        requestBytes + (progressKey === undefined ? 0 : keyBytes(progressKey));
      if (
        requestBytes > maxKeyBytes ||
        (progressKey !== undefined &&
          (keyBytes(progressKey) > maxKeyBytes || activeClientProgress.has(progressKey))) ||
        pendingClient.has(requestKey) ||
        pendingClient.size >= maxPending ||
        retainedBytes + retainedRequestBytes > maxPendingBytes
      ) {
        return false;
      }
      pendingClient.set(requestKey, {
        method,
        progressKey,
        retainedBytes: retainedRequestBytes,
        forwarded: false,
      });
      retainedBytes += retainedRequestBytes;
      if (progressKey !== undefined) activeClientProgress.set(progressKey, requestKey);
      return true;
    },
    markClientRequestForwarded(message): boolean {
      if (!("id" in message)) return true;
      const id = requestIdOf(message);
      const method = message["method"];
      if (id === null || typeof method !== "string") return false;
      const request = pendingClient.get(key(id));
      if (request === undefined || request.method !== method) return false;
      request.forwarded = true;
      return true;
    },
    releaseClientRequest(message): void {
      if (!("id" in message)) return;
      const id = requestIdOf(message);
      if (id !== null) deleteClientRequest(key(id));
    },
    canCancelRequest(id): boolean {
      if (!isProtocolId(id)) return false;
      prune(now());
      const request = pendingClient.get(key(id));
      return request?.forwarded === true && request.method !== "initialize";
    },
    canReportProgress(token): boolean {
      if (!isProgressToken(token)) return false;
      prune(now());
      return activeProgress.has(key(token));
    },
    consumeResponse(message): boolean {
      const id = requestIdOf(message);
      prune(now());
      return isResponseShaped(message) && id !== null && deleteServerRequest(key(id));
    },
  };
}
