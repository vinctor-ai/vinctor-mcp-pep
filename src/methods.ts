/**
 * JSON-RPC method policy: the ENUMERATION of every client → server MCP
 * method, and what the proxy must do with it (PKA-100).
 *
 * Before this policy existed only `tools/call` was gated — every other
 * method (`resources/read`, `prompts/get`, …) passed through to the wrapped
 * server unenforced and unaudited, a side door around the whole PEP. The
 * dispatch is now fail-closed by construction:
 *
 * - `gate-tools-call` — tools/call keeps its dedicated tool-mapping gate.
 * - `pass` — protocol lifecycle traffic that cannot reach data: the
 *   initialize handshake, ping, tools/list (tool-schema pinning stays the
 *   AGENTS.md follow-up), logging/setLevel, and the spec's client → server
 *   notifications.
 * - `enforce` — data-reaching methods, mapped to the Vinctor (action,
 *   resource) checks the proxy must ALL see permitted before forwarding:
 *     resources/list, resources/templates/list → read mcp/resources
 *     resources/read|subscribe|unsubscribe     → read over the file URI,
 *       through the SAME normalize + sensitive-overlay pipeline as tool
 *       path arguments (fsPathResource), so reading a `.env` resource is
 *       read:secret/env, never a quiet fs read
 *     prompts/list                             → read mcp/prompts
 *     prompts/get                              → read mcp/prompts/<name>
 *     completion/complete                      → read over the referenced
 *       prompt or resource
 * - `unknown` — EVERYTHING else: unknown methods, non-file resource URIs
 *   (this proxy cannot resolve what another scheme denotes), malformed
 *   params. The proxy always denies these fail-closed (and observes them).
 *   The unmapped-tool compatibility opt-out never applies to method dispatch.
 *
 * Server → client traffic is unaffected; client → server RESPONSES (replies
 * to server-initiated sampling/roots requests, no `method` field) are the
 * proxy's concern in proxy.ts, not this table's.
 */

import type { Action, MappedCall } from "./mapper.js";
import { fsPathResource } from "./mapper.js";
import { asRecord } from "./protocol.js";

export type MethodDecision =
  | { readonly verdict: "gate-tools-call"; readonly kind: "request" }
  | { readonly verdict: "pass"; readonly kind: "request" | "notification" }
  | {
      readonly verdict: "enforce";
      readonly kind: "request";
      readonly checks: readonly MappedCall[];
    }
  | { readonly verdict: "unknown" };

const UNKNOWN: MethodDecision = { verdict: "unknown" };

const enforce = (action: Action, resource: string): MethodDecision => ({
  verdict: "enforce",
  kind: "request",
  checks: [{ action, resource }],
});

/** Protocol lifecycle methods that cannot reach data — pass through. */
const PASS_METHODS: ReadonlyMap<string, "request" | "notification"> = new Map([
  ["initialize", "request"],
  ["ping", "request"],
  ["tools/list", "request"],
  ["logging/setLevel", "request"],
  ["notifications/initialized", "notification"],
  ["notifications/cancelled", "notification"],
  ["notifications/progress", "notification"],
  ["notifications/roots/list_changed", "notification"],
]);

/**
 * Resource for a `file:` URI, through the same pipeline as tool path
 * arguments (percent-decoded first — `%2Eenv` IS `.env` to the server's
 * opener). The WHATWG URL parser resolves every dot-segment spelling before
 * we see the pathname, exactly like a compliant server does, so the mapped
 * resource is the RESOLVED target. Null for anything this proxy cannot
 * resolve to a host path: other schemes, a non-local file host, undecodable
 * escapes, an empty resolved path.
 */
function fileUriResource(uri: unknown): string | null {
  if (typeof uri !== "string") return null;
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return null;
  }
  if (url.protocol !== "file:") return null;
  if (url.host !== "" && url.host !== "localhost") return null;
  if (url.search !== "" || url.hash !== "") return null;
  let path: string;
  try {
    path = decodeURIComponent(url.pathname);
  } catch {
    return null;
  }
  return fsPathResource(path);
}

/** One prompt-name resource segment; the readSegment rules (never spliced). */
function promptResource(name: unknown): string | null {
  if (typeof name !== "string" || name.length === 0) return null;
  if (name.includes("\0") || name.includes("/") || name.includes("\\")) return null;
  if (name === "." || name === "..") return null;
  return `mcp/prompts/${name}`;
}

export function decideMethod(method: string, params: unknown): MethodDecision {
  if (method === "tools/call") {
    return { verdict: "gate-tools-call", kind: "request" };
  }
  const passKind = PASS_METHODS.get(method);
  if (passKind !== undefined) return { verdict: "pass", kind: passKind };
  const p = asRecord(params);
  switch (method) {
    case "resources/list":
    case "resources/templates/list":
      return enforce("read", "mcp/resources");
    case "resources/read":
    case "resources/subscribe":
    case "resources/unsubscribe": {
      const resource = fileUriResource(p?.["uri"]);
      return resource === null ? UNKNOWN : enforce("read", resource);
    }
    case "prompts/list":
      return enforce("read", "mcp/prompts");
    case "prompts/get": {
      const resource = promptResource(p?.["name"]);
      return resource === null ? UNKNOWN : enforce("read", resource);
    }
    case "completion/complete": {
      const ref = asRecord(p?.["ref"]);
      if (ref?.["type"] === "ref/prompt") {
        const resource = promptResource(ref["name"]);
        return resource === null ? UNKNOWN : enforce("read", resource);
      }
      if (ref?.["type"] === "ref/resource") {
        const resource = fileUriResource(ref["uri"]);
        return resource === null ? UNKNOWN : enforce("read", resource);
      }
      return UNKNOWN;
    }
    default:
      return UNKNOWN;
  }
}
