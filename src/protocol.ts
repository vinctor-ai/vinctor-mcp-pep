export type JsonRpcId = string | number | null;

export function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function isProtocolId(value: unknown): value is string | number {
  return typeof value === "string" || (typeof value === "number" && Number.isSafeInteger(value));
}

export function isProgressToken(value: unknown): value is string | number {
  return typeof value === "string" || (typeof value === "number" && Number.isFinite(value));
}

export function requestIdOf(msg: Record<string, unknown>): JsonRpcId {
  const id = msg["id"];
  return isProtocolId(id) ? id : null;
}

export function hasValidEnvelope(msg: Record<string, unknown>): boolean {
  if (msg["jsonrpc"] !== "2.0") return false;
  if ("id" in msg && requestIdOf(msg) === null) return false;

  if ("method" in msg) {
    if ("result" in msg || "error" in msg) return false;
    if (!("params" in msg)) return true;
    const params = asRecord(msg["params"]);
    if (params === null) return false;
    if (params["_meta"] === undefined) return true;
    const meta = asRecord(params["_meta"]);
    return (
      meta !== null &&
      (!("id" in msg) ||
        meta["progressToken"] === undefined ||
        isProgressToken(meta["progressToken"]))
    );
  }

  return !("params" in msg);
}

export function isResponseShaped(msg: Record<string, unknown>): boolean {
  if ("method" in msg || requestIdOf(msg) === null) return false;
  const hasResult = "result" in msg;
  const hasError = "error" in msg;
  if (hasResult === hasError) return false;
  if (!hasError) {
    const result = asRecord(msg["result"]);
    return result !== null && (result["_meta"] === undefined || asRecord(result["_meta"]) !== null);
  }

  const error = asRecord(msg["error"]);
  return (
    error !== null &&
    typeof error["code"] === "number" &&
    Number.isInteger(error["code"]) &&
    typeof error["message"] === "string"
  );
}

const LOG_LEVELS: ReadonlySet<string> = new Set([
  "debug",
  "info",
  "notice",
  "warning",
  "error",
  "critical",
  "alert",
  "emergency",
]);

function hasValidClientCapabilities(value: unknown): boolean {
  const capabilities = asRecord(value);
  if (capabilities === null) return false;

  const experimental = capabilities["experimental"];
  if (experimental !== undefined) {
    const entries = asRecord(experimental);
    if (entries === null || Object.values(entries).some((item) => asRecord(item) === null)) {
      return false;
    }
  }

  const rootsValue = capabilities["roots"];
  if (rootsValue !== undefined) {
    const roots = asRecord(rootsValue);
    if (
      roots === null ||
      (roots["listChanged"] !== undefined && typeof roots["listChanged"] !== "boolean")
    ) {
      return false;
    }
  }

  for (const name of ["sampling", "elicitation"]) {
    const capability = capabilities[name];
    if (capability !== undefined && asRecord(capability) === null) return false;
  }
  return true;
}

export function hasValidPassParams(method: string, params: unknown): boolean {
  const p = asRecord(params);
  switch (method) {
    case "initialize": {
      const clientInfo = asRecord(p?.["clientInfo"]);
      return (
        p !== null &&
        typeof p["protocolVersion"] === "string" &&
        hasValidClientCapabilities(p["capabilities"]) &&
        clientInfo !== null &&
        typeof clientInfo["name"] === "string" &&
        typeof clientInfo["version"] === "string" &&
        (clientInfo["title"] === undefined || typeof clientInfo["title"] === "string")
      );
    }
    case "logging/setLevel":
      return p !== null && typeof p["level"] === "string" && LOG_LEVELS.has(p["level"]);
    case "notifications/cancelled": {
      const requestId = p?.["requestId"];
      return (
        p !== null &&
        isProtocolId(requestId) &&
        (p["reason"] === undefined || typeof p["reason"] === "string")
      );
    }
    case "notifications/progress": {
      const token = p?.["progressToken"];
      return (
        p !== null &&
        isProgressToken(token) &&
        typeof p["progress"] === "number" &&
        Number.isFinite(p["progress"]) &&
        (p["total"] === undefined ||
          (typeof p["total"] === "number" && Number.isFinite(p["total"]))) &&
        (p["message"] === undefined || typeof p["message"] === "string")
      );
    }
    case "tools/list":
      return p === null
        ? params === undefined
        : p["cursor"] === undefined || typeof p["cursor"] === "string";
    case "ping":
    case "notifications/initialized":
    case "notifications/roots/list_changed":
      return params === undefined || p !== null;
    default:
      return false;
  }
}

function hasValidCursorParams(params: unknown): boolean {
  const p = asRecord(params);
  return p === null
    ? params === undefined
    : p["cursor"] === undefined || typeof p["cursor"] === "string";
}

function isStringRecord(value: unknown): boolean {
  const record = asRecord(value);
  return record !== null && Object.values(record).every((item) => typeof item === "string");
}

export function hasValidEnforcedParams(method: string, params: unknown): boolean {
  const p = asRecord(params);
  switch (method) {
    case "resources/list":
    case "resources/templates/list":
    case "prompts/list":
      return hasValidCursorParams(params);
    case "resources/read":
    case "resources/subscribe":
    case "resources/unsubscribe":
      return p !== null && typeof p["uri"] === "string";
    case "prompts/get":
      return (
        p !== null &&
        typeof p["name"] === "string" &&
        (p["arguments"] === undefined || isStringRecord(p["arguments"]))
      );
    case "completion/complete": {
      const ref = asRecord(p?.["ref"]);
      const argument = asRecord(p?.["argument"]);
      const contextValue = p?.["context"];
      const context = contextValue === undefined ? null : asRecord(contextValue);
      return (
        p !== null &&
        ref !== null &&
        argument !== null &&
        typeof argument["name"] === "string" &&
        typeof argument["value"] === "string" &&
        (contextValue === undefined ||
          (context !== null &&
            (context["arguments"] === undefined || isStringRecord(context["arguments"]))))
      );
    }
    default:
      return false;
  }
}
