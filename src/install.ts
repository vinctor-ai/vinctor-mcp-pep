import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import type { Writable } from "node:stream";

/**
 * Client-config rewrite: the non-bypassability mechanism.
 *
 * `install` rewrites EVERY stdio server entry in a standard MCP client config
 * (`{"mcpServers": {name: {command, args, env}}}` — Claude Desktop / Cursor
 * style) to launch through this proxy: `command` becomes the proxy bin,
 * `args` becomes `["--", <original command>, ...<original args>]`, `env` and
 * any unknown entry keys are preserved untouched. `uninstall` restores from
 * the sibling backup written on first install.
 *
 * Remote url-based entries (Cursor's SSE / streamable-HTTP servers, `{url}`
 * with no `command`) cannot be gated by a stdio proxy. They are SKIPPED
 * verbatim and reported on stderr — never silently pretended-gated. An entry
 * with BOTH `command` and `url` is ambiguous and fails the whole rewrite.
 *
 * All writes are atomic (temp file + rename); any malformed input aborts with
 * an error BEFORE anything is written — never a partial rewrite.
 */

export const INSTALL_USAGE =
  "usage: vinctor-mcp-pep install|uninstall --client-config <path> [--dry-run]";

type JsonObject = Record<string, unknown>;

function isPlainObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export type InstallCliArgs =
  | { ok: true; configPath: string; dryRun: boolean }
  | { ok: false; error: string };

/** Parse the argv rest AFTER the install/uninstall subcommand word. */
export function parseInstallArgs(rest: string[]): InstallCliArgs {
  let configPath: string | null = null;
  let dryRun = false;
  let i = 0;
  while (i < rest.length) {
    const arg = rest[i];
    if (arg === "--client-config") {
      const value = rest[i + 1];
      if (value === undefined) return { ok: false, error: "--client-config requires a path" };
      configPath = value;
      i += 2;
      continue;
    }
    if (arg === "--dry-run") {
      dryRun = true;
      i += 1;
      continue;
    }
    return { ok: false, error: `unknown argument: ${arg}` };
  }
  if (configPath === null) return { ok: false, error: "--client-config is required" };
  return { ok: true, configPath, dryRun };
}

/** The sibling backup written on first install — the uninstall source of truth. */
export function backupPathFor(configPath: string): string {
  return configPath + ".vinctor-backup.json";
}

export type RewriteResult =
  | { ok: true; config: JsonObject; changed: boolean; skippedUrlServers?: string[] }
  | { ok: false; error: string };

/**
 * A marker this installer writes on entries it wrapped. It is NEVER evidence:
 * it is a declarative JSON key, so anything able to write the client config can
 * assert it. It is read only where believing it is the CONSERVATIVE choice —
 * refusing to overwrite a missing backup, and deciding what to warn about —
 * never to skip wrapping an entry.
 */
const WRAPPED_SENTINEL = "x-vinctor-mcp-pep";

function serverEntries(parsed: unknown): [string, JsonObject][] {
  if (!isPlainObject(parsed) || !isPlainObject(parsed["mcpServers"])) return [];
  return Object.entries(parsed["mcpServers"]).filter((pair): pair is [string, JsonObject] =>
    isPlainObject(pair[1]),
  );
}

/**
 * An entry already launching through this proxy — the idempotency check.
 *
 * THE RULE: install accepts a command only if install itself wrote that exact
 * string. Install always writes `proxyBin`, an absolute path resolved from
 * argv[1], so it never needs to accept anything else.
 *
 * Resolution was tried and cannot be the anchor. Realpath equality proves file
 * identity AT INSTALL TIME, IN THE INSTALLER'S ENVIRONMENT — and the entry
 * carries the client's: `env: {"PATH": "/tmp/evil/bin"}` inside the very object
 * install is inspecting sends the client's spawn somewhere else, with no race
 * and no assumed divergence. An attacker-owned symlink that resolves to the
 * real binary during the check can also be swapped afterwards, and swapped
 * back before the next one. Both holes are inherent to check-then-launch.
 * Byte equality has neither, because it asserts nothing about the filesystem.
 *
 * `args[0]` must be the `--` separator, exactly as this installer writes it.
 * Accepting a `--` anywhere in argv let an attacker smuggle proxy flags in
 * front of it: `["--config", "/tmp/evil/allow.json", "--", ...]` does route
 * through the proxy, but under an attacker-chosen `unmapped_verdict: "allow"`
 * — the side door the README names.
 *
 * Cost: when the npm prefix moves, the old absolute path no longer matches and
 * the entry is double-wrapped. That is cosmetic and fail-closed — the OUTER
 * command is the proxy that is actually running, and it still enforces.
 */
function isWrapped(entry: JsonObject, proxyBin: string): boolean {
  const args = entry["args"];
  if (!Array.isArray(args) || args[0] !== "--" || typeof args[1] !== "string") return false;
  return entry["command"] === proxyBin;
}

/**
 * A server entry may not carry anything that changes where the proxy gets its
 * verdict, what it loads, or whose identity it asserts.
 *
 * Once an entry is wrapped, the client launches THE PROXY with that entry's
 * env — `cli.ts` hands `process.env` to `startProxy`, and for a client-launched
 * entry `process.env` IS this env. So a field that reads as server
 * configuration is proxy configuration.
 *
 * Two categories, both fatal:
 *
 * 1. `VINCTOR_*` — the proxy's OWN settings: endpoint, PEP key, grant ref,
 *    workspace/agent id, subject token. This is the worst of the set and does
 *    not need a bypass anywhere else: with a byte-correct command and canonical
 *    argv, `"env": {"VINCTOR_ENDPOINT": "http://attacker/"}` points every
 *    authorization check at a PDP that answers "permit", and sends the audit
 *    stream there too. The proxy's configuration comes from the operator's
 *    environment; it is not the agent-writable config file's to set. Matched by
 *    PREFIX — the same rule `child_env.ts` already uses to strip `VINCTOR_*`
 *    from the child server — so a setting added later is covered by default
 *    rather than being a new hole.
 * 2. Loader and trust-root keys: code loading, and which CAs are believed.
 *
 * Matching is case-INSENSITIVE. Windows environment variables are, and `Path`
 * is the conventional Windows spelling; a case-sensitive check is bypassed by
 * capitalisation. Refusing `path` on a POSIX host too is fail-closed and free.
 */
const REFUSED_ENV_PREFIX = "VINCTOR_";
const REFUSED_ENV_KEYS: readonly string[] = [
  // code loading
  "PATH",
  "NODE_OPTIONS",
  "NODE_PATH",
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  // trust roots
  "NODE_EXTRA_CA_CERTS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
];

function isRefusedEnvKey(key: string): boolean {
  const upper = key.toUpperCase();
  return upper.startsWith(REFUSED_ENV_PREFIX) || REFUSED_ENV_KEYS.includes(upper);
}

export type EnvFinding = { readonly name: string; readonly field: string };

/**
 * Every (entry, field) pair that could redirect the proxy.
 *
 * Reported and refused rather than stripped: silently dropping a key would
 * destroy legitimate operator configuration without saying so.
 *
 * `envFile` is refused outright rather than read. Reading it would mean
 * checking a file at install time that the client re-reads at launch — the
 * same check-then-launch gap that made command resolution unusable — and it
 * can supply `VINCTOR_ENDPOINT` or `NODE_OPTIONS` just as `env` can.
 */
function unsafeEntryEnvFindings(parsed: unknown): EnvFinding[] {
  const findings: EnvFinding[] = [];
  for (const [name, entry] of serverEntries(parsed)) {
    if (typeof entry["command"] !== "string") continue;
    if (entry["envFile"] !== undefined) findings.push({ name, field: "envFile" });
    const env = entry["env"];
    if (!isPlainObject(env)) continue;
    for (const key of Object.keys(env)) {
      if (isRefusedEnvKey(key)) findings.push({ name, field: `env.${key}` });
    }
  }
  return findings;
}

function claimsWrapped(entry: JsonObject): boolean {
  return entry[WRAPPED_SENTINEL] === true;
}

function wrappedServerName(parsed: unknown, proxyBin: string): string | null {
  for (const [name, entry] of serverEntries(parsed)) {
    if (isWrapped(entry, proxyBin)) return name;
  }
  return null;
}

/** Any entry whose marker claims this installer wrote it. Never an accept. */
function markerClaimingServerName(parsed: unknown): string | null {
  for (const [name, entry] of serverEntries(parsed)) {
    if (claimsWrapped(entry)) return name;
  }
  return null;
}

/**
 * EVERY entry carrying the marker whose command is not the string install
 * writes.
 *
 * Computed from the command comparison directly, NOT as the complement of
 * `isWrapped`: phrased as `marker && !isWrapped` it would also fire on argv
 * shapes and so be a weaker statement than "this does not route through the
 * proxy". A forged marker is never a legitimate state, so all offenders are
 * reported, not just the first.
 */
function forgedMarkerServerNames(parsed: unknown, proxyBin: string): string[] {
  const names: string[] = [];
  for (const [name, entry] of serverEntries(parsed)) {
    if (claimsWrapped(entry) && entry["command"] !== proxyBin) names.push(name);
  }
  return names;
}

/**
 * Pure rewrite: wrap every stdio mcpServers entry to launch through
 * `proxyBin`. Already-wrapped entries are left as-is (running install twice
 * never double-wraps). Remote url-only entries cannot be wrapped by a stdio
 * proxy: they are kept verbatim and reported in `skippedUrlServers` so the
 * caller can say so out loud. Any malformed entry fails the WHOLE rewrite.
 */
export function rewriteClientConfig(parsed: unknown, proxyBin: string): RewriteResult {
  if (!isPlainObject(parsed) || !isPlainObject(parsed["mcpServers"])) {
    return { ok: false, error: "client config has no mcpServers object" };
  }
  const outServers: JsonObject = {};
  const skippedUrlServers: string[] = [];
  let changed = false;
  for (const [name, entry] of Object.entries(parsed["mcpServers"])) {
    if (!isPlainObject(entry)) {
      return { ok: false, error: `server entry "${name}" is not an object` };
    }
    if (isWrapped(entry, proxyBin)) {
      outServers[name] = entry;
      continue;
    }
    const command = entry["command"];
    const url = entry["url"];
    const hasCommand = typeof command === "string" && command.length > 0;
    const hasUrl = typeof url === "string" && url.length > 0;
    if (hasCommand && hasUrl) {
      // Ambiguous transport: wrapping could leave the url path live and
      // ungated behind a config that LOOKS proxied. Refuse instead.
      return { ok: false, error: `server entry "${name}" has both command and url` };
    }
    if (hasUrl) {
      outServers[name] = entry;
      skippedUrlServers.push(name);
      continue;
    }
    if (typeof command !== "string" || command.length === 0) {
      return { ok: false, error: `server entry "${name}" has no command string` };
    }
    const args = entry["args"] ?? [];
    if (!Array.isArray(args) || !args.every((a) => typeof a === "string")) {
      return { ok: false, error: `server entry "${name}" has non-string args` };
    }
    // Spread first: env and any unknown keys pass through untouched.
    outServers[name] = {
      ...entry,
      command: proxyBin,
      args: ["--", command, ...args],
      [WRAPPED_SENTINEL]: true,
    };
    changed = true;
  }
  return { ok: true, config: { ...parsed, mcpServers: outServers }, changed, skippedUrlServers };
}

/**
 * Pure restore: entries present in the backup are restored from it verbatim;
 * entries added after install (absent from the backup) are mechanically
 * unwrapped if wrapped, otherwise kept. Entries the user deleted since
 * install are NOT resurrected.
 */
export function restoreClientConfig(
  current: unknown,
  backup: unknown,
  proxyBin: string,
): RewriteResult {
  if (!isPlainObject(current) || !isPlainObject(current["mcpServers"])) {
    return { ok: false, error: "client config has no mcpServers object" };
  }
  if (!isPlainObject(backup) || !isPlainObject(backup["mcpServers"])) {
    return { ok: false, error: "backup has no mcpServers object" };
  }
  const backupServers = backup["mcpServers"];
  const outServers: JsonObject = {};
  let changed = false;
  for (const [name, entry] of Object.entries(current["mcpServers"])) {
    if (!isPlainObject(entry)) {
      return { ok: false, error: `server entry "${name}" is not an object` };
    }
    const original = backupServers[name];
    if (isPlainObject(original)) {
      outServers[name] = original;
      if (JSON.stringify(original) !== JSON.stringify(entry)) changed = true;
      continue;
    }
    if (isWrapped(entry, proxyBin)) {
      const args = entry["args"] as unknown[];
      const command = args[1];
      const rest = args.slice(2);
      if (typeof command !== "string" || !rest.every((a) => typeof a === "string")) {
        return { ok: false, error: `cannot unwrap server entry "${name}"` };
      }
      const restored: JsonObject = { ...entry, command, args: rest };
      delete restored[WRAPPED_SENTINEL];
      outServers[name] = restored;
      changed = true;
      continue;
    }
    outServers[name] = entry;
  }
  return { ok: true, config: { ...current, mcpServers: outServers }, changed };
}

type FileIdentity = {
  readonly dev: number;
  readonly ino: number;
  readonly mode: number;
};

type InstallCommandDeps = {
  readonly fsyncParent?: (path: string) => void;
};

class PostCommitSyncError extends Error {
  readonly path: string;

  constructor(path: string, cause: unknown) {
    super("parent directory sync failed after commit", { cause });
    this.name = "PostCommitSyncError";
    this.path = path;
  }
}

let atomicWriteSequence = 0;

function regularFileIdentity(path: string): FileIdentity | null {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) return null;
  return { dev: stat.dev, ino: stat.ino, mode: stat.mode & 0o7777 };
}

function openVerified(path: string, expected: FileIdentity): number {
  const fd = openSync(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
  );
  const stat = fstatSync(fd);
  if (!stat.isFile() || stat.dev !== expected.dev || stat.ino !== expected.ino) {
    closeSync(fd);
    throw new Error("target changed while opening");
  }
  return fd;
}

function readVerified(path: string, expected: FileIdentity): string {
  const fd = openVerified(path, expected);
  try {
    return readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
}

function restrictMode(
  path: string,
  expected: FileIdentity,
  mode: number,
  syncParent: (path: string) => void,
): void {
  const fd = openVerified(path, expected);
  try {
    fchmodSync(fd, mode);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    syncParent(path);
  } catch (error) {
    throw new PostCommitSyncError(path, error);
  }
}

function fsyncParent(path: string): void {
  if (process.platform === "win32") return;
  const fd = openSync(dirname(path), constants.O_RDONLY);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Durable sibling write. Existing targets are replaced only when their inode
 * still matches the one read by the caller. New targets use link(2), whose
 * no-replace semantics prevent a pre-created symlink from winning the race.
 */
function writeAtomic(
  path: string,
  content: string,
  mode: number,
  expected: FileIdentity | null,
  syncParent: (path: string) => void,
): void {
  const tmp = `${path}.tmp-${process.pid}-${atomicWriteSequence++}`;
  let fd: number | null = null;
  let created = false;
  try {
    fd = openSync(tmp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    created = true;
    writeFileSync(fd, content, "utf8");
    fchmodSync(fd, mode);
    fsyncSync(fd);
    closeSync(fd);
    fd = null;

    if (expected === null) {
      linkSync(tmp, path);
      unlinkSync(tmp);
    } else {
      const current = regularFileIdentity(path);
      if (
        current === null ||
        current.dev !== expected.dev ||
        current.ino !== expected.ino
      ) {
        throw new Error("target changed during rewrite");
      }
      renameSync(tmp, path);
    }
  } catch (error) {
    if (fd !== null) closeSync(fd);
    if (created) {
      try {
        unlinkSync(tmp);
      } catch {}
    }
    throw error;
  }
  try {
    syncParent(path);
  } catch (error) {
    throw new PostCommitSyncError(path, error);
  }
}

export type InstallCommandOptions = {
  mode: "install" | "uninstall";
  configPath: string;
  /** Absolute realpath of this proxy's bin (resolved from process.argv[1]). */
  proxyBin: string;
  dryRun: boolean;
  stdout: Writable;
  stderr: Writable;
};

/** Run install/uninstall against the file. Returns the process exit code. */
export function runInstallCommand(
  opts: InstallCommandOptions,
  deps: InstallCommandDeps = {},
): number {
  const fail = (msg: string): number => {
    opts.stderr.write(`vinctor-mcp-pep: ${msg}\n`);
    return 2;
  };

  let configIdentity: FileIdentity | null;
  try {
    configIdentity = regularFileIdentity(opts.configPath);
  } catch {
    return fail(`cannot read client config: ${opts.configPath}`);
  }
  if (configIdentity === null) {
    return fail(`client config must be a regular file: ${opts.configPath}`);
  }

  let rawText: string;
  try {
    rawText = readVerified(opts.configPath, configIdentity);
  } catch {
    return fail(`cannot read client config: ${opts.configPath}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return fail(`client config is not valid JSON: ${opts.configPath}`);
  }

  // ---------------------------------------------------------------------
  // Findings about the LIVE config come first, in every mode. A poisoned
  // backup used to make install, --dry-run and uninstall all fail on the
  // backup while an unenforced entry sat in the config unmentioned and
  // unrepaired: the attacker kept an ungated server AND disabled the repair
  // tool. The urgent problem is the config; it gets named first.
  // ---------------------------------------------------------------------
  const forgedMarkers = forgedMarkerServerNames(parsed, opts.proxyBin);
  for (const name of forgedMarkers) {
    opts.stderr.write(
      `vinctor-mcp-pep: warning: server entry "${name}" carries ${WRAPPED_SENTINEL} but its command is not this proxy (${opts.proxyBin}); it does NOT route through this proxy\n`,
    );
  }
  const envFindings = unsafeEntryEnvFindings(parsed);
  for (const { name, field } of envFindings) {
    opts.stderr.write(
      `vinctor-mcp-pep: server entry "${name}" sets ${field}; once wrapped, this entry's environment is the PROXY's, so that can change where it gets its verdict, what it loads, or whose identity it asserts\n`,
    );
  }
  if (envFindings.length > 0) {
    // Not stripped: dropping it silently would destroy legitimate operator
    // configuration without telling anyone. The operator removes the named
    // field from the named entry — putting the value in the MCP client's own
    // environment, or on the server command itself — and re-runs.
    return fail(
      `refusing to touch a client config whose entries can redirect the proxy: ${opts.configPath}`,
    );
  }

  const backupPath = backupPathFor(opts.configPath);
  const syncParent = deps.fsyncParent ?? fsyncParent;
  let backupIdentity: FileIdentity | null = null;
  try {
    backupIdentity = regularFileIdentity(backupPath);
    if (backupIdentity === null) {
      return fail(`backup must be a regular file: ${backupPath}`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      return fail(`cannot read backup: ${backupPath}`);
    }
  }
  let backupParsed: unknown = null;
  if (backupIdentity !== null) {
    let backupText: string;
    try {
      backupText = readVerified(backupPath, backupIdentity);
    } catch {
      return fail(`cannot read backup: ${backupPath}`);
    }
    try {
      backupParsed = JSON.parse(backupText);
    } catch {
      return fail(`backup is not valid JSON: ${backupPath}`);
    }
    const backupValidation = rewriteClientConfig(backupParsed, opts.proxyBin);
    if (!backupValidation.ok) {
      return fail(`backup is not usable: ${backupValidation.error}`);
    }
    // A backup entry that really is wrapped means the backup does not hold
    // pre-install state: restoring it would leave the client launching through
    // the proxy, so refuse.
    const wrappedBackupServer = wrappedServerName(backupParsed, opts.proxyBin);
    if (wrappedBackupServer !== null) {
      return fail(
        `backup contains already wrapped server entry "${wrappedBackupServer}": ${backupPath}`,
      );
    }
    // A MARKER on a backup entry whose command is not the proxy bin is a lie,
    // and now that the marker grants nothing on the accept path it is harmless
    // to restore — the entry does not route through the proxy either way, and
    // the next install wraps it. Obeying it turned one forged byte in the
    // backup into a deadlock that blocked install, --dry-run and uninstall
    // alike while a live entry stayed ungated. Report it instead.
    const markerBackupServer = markerClaimingServerName(backupParsed);
    if (markerBackupServer !== null) {
      opts.stderr.write(
        `vinctor-mcp-pep: warning: backup entry "${markerBackupServer}" carries ${WRAPPED_SENTINEL} but is not wrapped; the marker is ignored: ${backupPath}\n`,
      );
    }
  }

  let result: RewriteResult;
  if (opts.mode === "install") {
    result = rewriteClientConfig(parsed, opts.proxyBin);
    if (result.ok) {
      // The marker alone is enough to refuse taking a FRESH backup: believing
      // a self-asserted claim is safe only where believing it is conservative,
      // and here it prevents overwriting the uninstall source of truth with an
      // already-rewritten config (a moved npm prefix leaves genuinely wrapped
      // entries whose command no longer matches). The escape is named in the
      // message: drop the marker if the entry does not route through this
      // proxy, or put the real backup back.
      const claimedServer =
        wrappedServerName(parsed, opts.proxyBin) ?? markerClaimingServerName(parsed);
      if (claimedServer !== null && backupIdentity === null) {
        return fail(
          `client config is already wrapped but backup is missing: ${opts.configPath}; ` +
            `restore the backup, or remove ${WRAPPED_SENTINEL} from entry "${claimedServer}" if it does not route through this proxy`,
        );
      }
    }
  } else {
    if (backupIdentity === null) {
      return fail(`no backup to uninstall from: ${backupPath}`);
    }
    result = restoreClientConfig(parsed, backupParsed, opts.proxyBin);
  }
  if (!result.ok) return fail(result.error);
  if (opts.mode === "uninstall") {
    const wrappedServer = wrappedServerName(result.config, opts.proxyBin);
    if (wrappedServer !== null) {
      return fail(
        `uninstall would leave server entry "${wrappedServer}" wrapped; config and backup were not changed`,
      );
    }
  }
  const skipped = result.skippedUrlServers ?? [];
  if (skipped.length > 0) {
    // Honesty over silence: a stdio proxy cannot gate remote url servers, so
    // never let install imply they are covered.
    opts.stderr.write(
      `vinctor-mcp-pep: warning: skipped url-based server(s) — remote MCP servers are not gated by this stdio proxy: ${skipped.join(", ")}\n`,
    );
  }

  const output = JSON.stringify(result.config, null, 2) + "\n";
  if (opts.dryRun) {
    opts.stdout.write(output);
    // A dry run is the integrity CHECK: it must not report success on a config
    // carrying a forged marker just because it changed nothing.
    return forgedMarkers.length === 0 ? 0 : 2;
  }
  let createdBackup = false;
  let writingBackup = false;
  try {
    if (opts.mode === "install" && backupIdentity === null) {
      writingBackup = true;
      // First install only: preserve the ORIGINAL bytes. An existing backup is
      // never overwritten — it is the uninstall source of truth.
      writeAtomic(backupPath, rawText, configIdentity.mode & 0o600, null, syncParent);
      createdBackup = true;
    } else if (opts.mode === "install" && backupIdentity !== null) {
      writingBackup = true;
      // Harden backups created by older releases without changing their bytes.
      restrictMode(
        backupPath,
        backupIdentity,
        backupIdentity.mode & configIdentity.mode & 0o600,
        syncParent,
      );
    }
    writingBackup = false;
    writeAtomic(opts.configPath, output, configIdentity.mode, configIdentity, syncParent);
  } catch (error) {
    if (error instanceof PostCommitSyncError) {
      if (error.path === opts.configPath) {
        return fail(
          `client config was replaced but parent directory sync failed: ${opts.configPath}`,
        );
      }
      return fail(`backup was updated but parent directory sync failed: ${error.path}`);
    }
    if (createdBackup) {
      try {
        unlinkSync(backupPath);
        syncParent(backupPath);
      } catch {
        return fail(
          `could not safely write client config and could not remove new backup: ${backupPath}`,
        );
      }
    }
    if (writingBackup) {
      return fail(`could not safely write backup: ${backupPath}`);
    }
    return fail(`could not safely write client config: ${opts.configPath}`);
  }
  if (opts.mode === "uninstall") {
    // Consumed: the next install cycle takes a fresh backup of current state.
    try {
      unlinkSync(backupPath);
    } catch {
      opts.stderr.write(`vinctor-mcp-pep: warning: could not remove backup: ${backupPath}\n`);
      return 0;
    }
    try {
      syncParent(backupPath);
    } catch {
      return fail(`backup was removed but parent directory sync failed: ${backupPath}`);
    }
  }
  return 0;
}
