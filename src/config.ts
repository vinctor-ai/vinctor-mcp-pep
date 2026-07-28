import { readFileSync } from "node:fs";

/**
 * Proxy config file (`--config <path>`): JSON
 * `{"unmapped_verdict": "deny" | "allow"}`.
 *
 * Default is DENY (absent file, absent key). `"allow"` forwards unmapped
 * tools/call WITHOUT enforcement — an explicit operator opt-out per ADR 0011
 * that weakens the non-bypassability guarantee (documented loudly in the
 * README). Anything malformed (unreadable file, bad JSON, unknown value)
 * fails closed to deny AND surfaces one stderr warning line.
 */

export type UnmappedVerdict = "deny" | "allow";

export type LoadedProxyConfig = {
  unmappedVerdict: UnmappedVerdict;
  /** One operator-facing line to write to stderr, or null. */
  warning: string | null;
};

const DENY: LoadedProxyConfig = { unmappedVerdict: "deny", warning: null };

function denyWith(warning: string): LoadedProxyConfig {
  return { unmappedVerdict: "deny", warning };
}

/** Pure: parse config file text. Exported for unit testing. */
export function parseProxyConfigText(text: string): LoadedProxyConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return denyWith("config file is not valid JSON; unmapped tools stay DENY (fail-closed)");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return denyWith("config file is not a JSON object; unmapped tools stay DENY (fail-closed)");
  }
  const verdict = (parsed as { unmapped_verdict?: unknown }).unmapped_verdict;
  if (verdict === undefined || verdict === "deny") return DENY;
  if (verdict === "allow") return { unmappedVerdict: "allow", warning: null };
  return denyWith("config has an unknown unmapped_verdict; unmapped tools stay DENY (fail-closed)");
}

/** Load `--config`. A null path (flag not given) is the default: deny, silent. */
export function loadProxyConfig(configPath: string | null): LoadedProxyConfig {
  if (configPath === null) return DENY;
  let text: string;
  try {
    text = readFileSync(configPath, "utf8");
  } catch {
    return denyWith(
      "config file could not be read; unmapped tools stay DENY (fail-closed)",
    );
  }
  return parseProxyConfigText(text);
}
