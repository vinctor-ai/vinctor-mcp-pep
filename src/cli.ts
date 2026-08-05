#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { startProxy } from "./proxy.js";
import { parseInstallArgs, runInstallCommand, INSTALL_USAGE } from "./install.js";
import { loadProxyConfig } from "./config.js";

export const USAGE = [
  "usage: vinctor-mcp-pep [--config <path>] -- <server-cmd> [args...]",
  "       vinctor-mcp-pep install|uninstall --client-config <path> [--dry-run]",
].join("\n");

export type ParsedCliArgs =
  | { ok: true; configPath: string | null; command: string; args: string[] }
  | { ok: false; error: string };

/** Parse process.argv. Pure — exported for unit testing. */
export function parseCliArgs(argv: string[]): ParsedCliArgs {
  const rest = argv.slice(2);
  let configPath: string | null = null;
  let i = 0;
  while (i < rest.length) {
    const arg = rest[i];
    if (arg === undefined) break;
    if (arg === "--") {
      const serverArgv = rest.slice(i + 1);
      const command = serverArgv[0];
      if (command === undefined) return { ok: false, error: "missing server command after --" };
      return { ok: true, configPath, command, args: serverArgv.slice(1) };
    }
    if (arg === "--config") {
      const value = rest[i + 1];
      if (value === undefined || value === "--") {
        return { ok: false, error: "--config requires a path" };
      }
      configPath = value;
      i += 2;
      continue;
    }
    return { ok: false, error: `unknown argument: ${arg}` };
  }
  return { ok: false, error: "missing -- <server-cmd>" };
}

// Only run when invoked as the CLI entrypoint (not when imported). npm installs
// the bin as a symlink, so argv[1] must be realpath'd before comparing — a naive
// `file://${argv[1]}` guard silently no-ops the published binary, which for a
// fail-closed proxy would be a fail-OPEN.
const invokedAsMain = (() => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
})();

if (invokedAsMain) {
  const sub = process.argv[2];
  if (sub === "install" || sub === "uninstall") {
    const parsed = parseInstallArgs(process.argv.slice(3));
    if (!parsed.ok) {
      process.stderr.write(`vinctor-mcp-pep: ${parsed.error}\n${INSTALL_USAGE}\n`);
      process.exit(2);
    }
    // The rewritten entries must point at THIS bin by absolute path (same
    // realpath technique as the invokedAsMain guard above).
    const proxyBin = realpathSync(process.argv[1] as string);
    process.exit(
      runInstallCommand({
        mode: sub,
        configPath: parsed.configPath,
        proxyBin,
        dryRun: parsed.dryRun,
        stdout: process.stdout,
        stderr: process.stderr,
      }),
    );
  }
  const parsed = parseCliArgs(process.argv);
  if (!parsed.ok) {
    process.stderr.write(`vinctor-mcp-pep: ${parsed.error}\n${USAGE}\n`);
    process.exit(2);
  }
  const config = loadProxyConfig(parsed.configPath);
  if (config.warning !== null) {
    process.stderr.write(`vinctor-mcp-pep: ${config.warning}\n`);
  }
  const { done } = startProxy({
    unmappedVerdict: config.unmappedVerdict,
    command: parsed.command,
    args: parsed.args,
    clientIn: process.stdin,
    clientOut: process.stdout,
    clientErr: process.stderr,
    env: process.env,
  });
  process.exit(await done);
}
