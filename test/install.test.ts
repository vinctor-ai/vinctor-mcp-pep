import { describe, it, beforeEach } from "node:test";
import { strict as assert } from "node:assert";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import {
  parseInstallArgs,
  rewriteClientConfig,
  restoreClientConfig,
  runInstallCommand,
  backupPathFor,
} from "../src/install.js";

const PROXY_BIN = "/opt/vinctor/bin/vinctor-mcp-pep";

const SAMPLE = {
  otherTopLevelKey: { keep: "me" },
  mcpServers: {
    filesystem: {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
      env: { FS_ROOT: "/workspace" },
    },
    github: { command: "github-mcp" }, // partial shape: no args, no env
  },
};

// Cursor-style config: stdio entries (with Cursor extras like `type`) mixed
// with a remote url-based entry, which a stdio proxy cannot wrap. `envFile` is
// deliberately absent: it is refused (see the entry-field class table), so the
// supported Cursor shape puts the server's variables inline in `env`.
const CURSOR_SAMPLE = {
  mcpServers: {
    filesystem: {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
      env: { FS_ROOT: "/workspace" },
    },
    "typed-stdio": {
      type: "stdio",
      command: "python",
      args: ["server.py"],
      env: { PY_SERVER_ROOT: "/workspace" },
    },
    "linear-remote": {
      url: "https://mcp.linear.app/sse",
      headers: { Authorization: "Bearer TOKEN" },
    },
  },
};

type Sink = { stream: PassThrough; text: () => string };
function sink(): Sink {
  const stream = new PassThrough();
  let buf = "";
  stream.on("data", (c: Buffer) => (buf += c.toString("utf8")));
  return { stream, text: () => buf };
}

type RunResult = { code: number; stdout: string; stderr: string };
type RunDeps = {
  fsyncParent?: (path: string) => void;
};
function run(
  mode: "install" | "uninstall",
  configPath: string,
  dryRun = false,
  deps: RunDeps = {},
  overrides: { proxyBin?: string } = {},
): RunResult {
  const out = sink();
  const err = sink();
  const code = runInstallCommand({
    mode,
    configPath,
    proxyBin: overrides.proxyBin ?? PROXY_BIN,
    dryRun,
    stdout: out.stream,
    stderr: err.stream,
  }, deps);
  return { code, stdout: out.text(), stderr: err.text() };
}

/**
 * A decoy executable named like this package, in a throwaway directory. It is
 * never run: it exists so PATH/realpath resolution has something to find, the
 * way an attacker-planted shim earlier on PATH would.
 */
function decoyBin(dir: string, name = "vinctor-mcp-pep"): string {
  const binDir = mkdtempSync(join(dir, "bin-"));
  const path = join(binDir, name);
  writeFileSync(path, "#!/bin/sh\n# decoy fixture for install tests; never executed\nexit 0\n");
  chmodSync(path, 0o755);
  return path;
}

/**
 * Every command shape that must NOT be accepted as "already routing through
 * this proxy". `marker` entries additionally carry the sentinel, which is what
 * made the whole class dangerous: the key is declarative, so anything able to
 * write the client config can assert it.
 */
function poisonCommands(dir: string): { label: string; command: string }[] {
  const planted = decoyBin(dir);
  return [
    { label: "bare PATH name", command: "vinctor-mcp-pep" },
    { label: "absolute attacker path", command: planted },
    { label: "relative path", command: "./vinctor-mcp-pep" },
    { label: "user-writable bin dir", command: "/home/victim/.local/bin/vinctor-mcp-pep" },
    {
      label: "attacker-rooted package entry point",
      command: "/tmp/evil/vinctor-mcp-pep/dist/src/cli.js",
    },
    { label: "windows separators", command: "C:\\Users\\victim\\evil\\vinctor-mcp-pep" },
    { label: "mixed separators", command: "/tmp/evil\\vinctor-mcp-pep" },
    { label: "unnormalised traversal", command: "/opt/legit/../../tmp/evil/vinctor-mcp-pep" },
    { label: "package-relative entry point", command: "vinctor-mcp-pep/dist/src/cli.js" },
    { label: "unrelated command", command: "npx" },
  ];
}

/**
 * Every field a server entry can carry, with the verdict install must reach.
 *
 * The class property: **no field of a server entry may change where the proxy
 * gets its verdict, what it loads, or whose identity it asserts.** Once an
 * entry is wrapped, the client launches THE PROXY with this entry's env and
 * cwd — so a field that looks like server configuration is proxy
 * configuration.
 */
type EntryFieldCase = { label: string; patch: Record<string, unknown>; refused: boolean };

const refusedEnv = (label: string, env: Record<string, string>): EntryFieldCase => ({
  label,
  patch: { env },
  refused: true,
});

const ENTRY_FIELD_CASES: EntryFieldCase[] = [
  // Decision configuration — the proxy's own settings. Worst of the set: a
  // poisoned endpoint points every authorization check at an attacker's PDP
  // that answers "permit", and sends the audit stream there too.
  refusedEnv("env VINCTOR_ENDPOINT", { VINCTOR_ENDPOINT: "http://127.0.0.1:9" }),
  refusedEnv("env VINCTOR_PEP_KEY", { VINCTOR_PEP_KEY: "pep_decoy" }),
  refusedEnv("env VINCTOR_GRANT_REF", { VINCTOR_GRANT_REF: "grant_decoy" }),
  refusedEnv("env VINCTOR_SUBJECT_TOKEN", { VINCTOR_SUBJECT_TOKEN: "vat_decoy" }),
  refusedEnv("env vinctor_endpoint (lowercase)", { vinctor_endpoint: "http://127.0.0.1:9" }),
  refusedEnv("env Vinctor_Endpoint (mixed case)", { Vinctor_Endpoint: "http://127.0.0.1:9" }),
  // A setting that does not exist yet: the prefix rule must cover it, or every
  // future setting is a new hole.
  refusedEnv("env VINCTOR_FUTURE_SETTING", { VINCTOR_FUTURE_SETTING: "decoy" }),

  // Code loading.
  refusedEnv("env NODE_OPTIONS", { NODE_OPTIONS: "--import file:///tmp/decoy.mjs" }),
  refusedEnv("env node_options (lowercase)", { node_options: "--import file:///tmp/decoy.mjs" }),
  refusedEnv("env NODE_PATH", { NODE_PATH: "/tmp/decoy" }),
  refusedEnv("env PATH", { PATH: "/tmp/decoy/bin" }),
  refusedEnv("env Path (Windows spelling)", { Path: "/tmp/decoy/bin" }),
  refusedEnv("env path (lowercase)", { path: "/tmp/decoy/bin" }),
  refusedEnv("env LD_PRELOAD", { LD_PRELOAD: "/tmp/decoy.so" }),
  refusedEnv("env LD_LIBRARY_PATH", { LD_LIBRARY_PATH: "/tmp/decoy" }),
  refusedEnv("env DYLD_INSERT_LIBRARIES", { DYLD_INSERT_LIBRARIES: "/tmp/decoy.dylib" }),
  refusedEnv("env DYLD_LIBRARY_PATH", { DYLD_LIBRARY_PATH: "/tmp/decoy" }),

  // Trust roots: weaker (they need a network position) but the same class.
  refusedEnv("env NODE_EXTRA_CA_CERTS", { NODE_EXTRA_CA_CERTS: "/tmp/decoy-ca.pem" }),
  refusedEnv("env NODE_TLS_REJECT_UNAUTHORIZED", { NODE_TLS_REJECT_UNAUTHORIZED: "0" }),
  refusedEnv("env SSL_CERT_FILE", { SSL_CERT_FILE: "/tmp/decoy-ca.pem" }),
  refusedEnv("env SSL_CERT_DIR", { SSL_CERT_DIR: "/tmp/decoy-ca" }),

  // Env supplied out of band: install would have to read a file the client
  // re-reads later, which is the check-then-launch gap all over again.
  { label: "envFile", patch: { envFile: "/tmp/decoy/.env" }, refused: true },

  // Server configuration that reaches the SERVER, not the proxy: passed
  // through untouched.
  { label: "env FS_ROOT (benign)", patch: { env: { FS_ROOT: "/workspace" } }, refused: false },
  {
    label: "env GITHUB_TOKEN (benign, decoy value)",
    patch: { env: { GITHUB_TOKEN: "ghp_decoy_not_a_real_token" } },
    refused: false,
  },
  // cwd cannot change what the proxy executes: the command is absolute.
  { label: "cwd", patch: { cwd: "/tmp/decoy" }, refused: false },
  { label: "type (Cursor extra)", patch: { type: "stdio" }, refused: false },
  { label: "unknown passthrough key", patch: { "x-client-extra": { a: 1 } }, refused: false },
];

/** Fields whose behaviour is pinned by the command-check tests, not the table. */
const FIELDS_COVERED_ELSEWHERE = new Set([
  "command",
  "args",
  "url",
  "headers",
  "x-vinctor-mcp-pep",
]);

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
}

describe("parseInstallArgs", () => {
  it("parses --client-config and --dry-run", () => {
    assert.deepEqual(parseInstallArgs(["--client-config", "/tmp/c.json"]), {
      ok: true,
      configPath: "/tmp/c.json",
      dryRun: false,
    });
    assert.deepEqual(parseInstallArgs(["--dry-run", "--client-config", "/tmp/c.json"]), {
      ok: true,
      configPath: "/tmp/c.json",
      dryRun: true,
    });
  });

  it("rejects missing --client-config, missing value, and unknown args", () => {
    assert.ok(!parseInstallArgs([]).ok);
    assert.ok(!parseInstallArgs(["--client-config"]).ok);
    assert.ok(!parseInstallArgs(["--verbose"]).ok);
  });
});

describe("rewriteClientConfig (pure)", () => {
  it("wraps every entry through the proxy bin, preserving env and unknown keys", () => {
    const parsed = JSON.parse(
      JSON.stringify({
        mcpServers: {
          fs: { command: "npx", args: ["-y", "srv"], env: { A: "1" }, disabled: false },
        },
      }),
    ) as Record<string, unknown>;
    const r = rewriteClientConfig(parsed, PROXY_BIN);
    assert.ok(r.ok);
    const fs = (r.config["mcpServers"] as Record<string, unknown>)["fs"] as Record<string, unknown>;
    assert.equal(fs["command"], PROXY_BIN);
    assert.deepEqual(fs["args"], ["--", "npx", "-y", "srv"]);
    assert.deepEqual(fs["env"], { A: "1" }); // untouched
    assert.equal(fs["disabled"], false); // unknown keys preserved
    assert.equal(r.changed, true);
  });

  it("entry with no args wraps to just ['--', command]; no env key is invented", () => {
    const r = rewriteClientConfig({ mcpServers: { gh: { command: "github-mcp" } } }, PROXY_BIN);
    assert.ok(r.ok);
    const gh = (r.config["mcpServers"] as Record<string, unknown>)["gh"] as Record<string, unknown>;
    assert.deepEqual(gh["args"], ["--", "github-mcp"]);
    assert.equal("env" in gh, false);
  });

  it("is idempotent: an already-wrapped entry is not double-wrapped", () => {
    const first = rewriteClientConfig(SAMPLE, PROXY_BIN);
    assert.ok(first.ok);
    const second = rewriteClientConfig(first.config, PROXY_BIN);
    assert.ok(second.ok);
    assert.deepEqual(second.config, first.config);
    assert.equal(second.changed, false);
  });

  it("accepts a command only if install itself wrote that exact string", () => {
    // THE class property. Install always writes an absolute path, so the only
    // command it ever needs to accept is that exact string. Everything else —
    // a different spelling of the same file, a symlink or hardlink to it, a
    // bare name PATH happens to resolve to it — is re-wrapped.
    //
    // Resolution cannot be the anchor. Realpath equality proves file identity
    // at install time in the INSTALLER's environment, and the entry carries
    // the CLIENT's: `env: {"PATH": "/tmp/evil/bin"}` inside the very object
    // install is inspecting sends the client somewhere else. An attacker-owned
    // symlink can also be swapped after the check. Byte equality has no such
    // gap because it asserts nothing about the filesystem.
    const dir = mkdtempSync(join(tmpdir(), "vinctor-mcp-pep-class-"));
    const realBin = decoyBin(dir);
    const shim = decoyBin(dir);
    const symlinked = join(dir, "symlinked-vinctor-mcp-pep");
    symlinkSync(realBin, symlinked);
    const hardlinked = join(mkdtempSync(join(dir, "alt-")), "vinctor-mcp-pep");
    linkSync(realBin, hardlinked);

    const commands = [
      realBin, // the exact string install writes — the ONLY accept
      symlinked, // resolves to the same file
      hardlinked, // same inode, different string
      join(dirname(realBin), ".", "vinctor-mcp-pep"), // same file, other spelling
      shim, // planted shim, same basename
      "vinctor-mcp-pep", // bare name; PATH below resolves it to the real bin
      "./vinctor-mcp-pep",
      `${realBin} `,
      realBin.toUpperCase(),
      "/tmp/evil/vinctor-mcp-pep",
      "/home/victim/.local/bin/vinctor-mcp-pep",
      "/tmp/evil/vinctor-mcp-pep/dist/src/cli.js",
      "C:\\Users\\victim\\evil\\vinctor-mcp-pep",
      "/tmp/evil\\vinctor-mcp-pep",
      "/opt/legit/../../tmp/evil/vinctor-mcp-pep",
      "npx",
    ];

    // Real-proxy-first PATH: the deployed ordering, where a bare name really
    // does resolve to the genuine binary. It must STILL be re-wrapped — the
    // installer's PATH is not the client's.
    const savedPath = process.env["PATH"];
    process.env["PATH"] = `${dirname(realBin)}${delimiter}${dirname(shim)}`;
    try {
      for (const command of commands) {
        const parsed = {
          mcpServers: {
            filesystem: {
              command,
              args: ["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/"],
              "x-vinctor-mcp-pep": true,
            },
          },
        };
        const r = rewriteClientConfig(parsed, realBin);
        assert.ok(r.ok, command);
        assert.equal(r.changed, command !== realBin, `command=${JSON.stringify(command)}`);
      }
    } finally {
      process.env["PATH"] = savedPath;
    }
  });

  it("double-wraps rather than trusts a moved npm prefix (accepted cosmetic cost)", () => {
    const first = rewriteClientConfig(SAMPLE, "/old/prefix/bin/vinctor-mcp-pep");
    assert.ok(first.ok);
    const moved = rewriteClientConfig(first.config, "/new/prefix/bin/vinctor-mcp-pep");
    assert.ok(moved.ok);
    assert.equal(moved.changed, true);
    const filesystem = (moved.config["mcpServers"] as Record<string, Record<string, unknown>>)[
      "filesystem"
    ];
    // Fail-closed: the OUTER command is the proxy that is actually running.
    assert.equal(filesystem?.["command"], "/new/prefix/bin/vinctor-mcp-pep");
    assert.equal((filesystem?.["args"] as unknown[])[0], "--");
    assert.equal((filesystem?.["args"] as unknown[])[1], "/old/prefix/bin/vinctor-mcp-pep");
  });

  it("leaves no entry field unclassified", () => {
    // A field that is merely passed through must be classified in
    // ENTRY_FIELD_CASES, not pass by omission. Adding one to a fixture without
    // deciding its verdict fails here.
    const seen = new Set<string>();
    for (const sample of [SAMPLE, CURSOR_SAMPLE]) {
      for (const entry of Object.values(sample.mcpServers) as Record<string, unknown>[]) {
        for (const field of Object.keys(entry)) seen.add(field);
      }
    }
    const classified = new Set(
      ENTRY_FIELD_CASES.flatMap((c) => Object.keys(c.patch)),
    );
    for (const field of seen) {
      assert.ok(
        classified.has(field) || FIELDS_COVERED_ELSEWHERE.has(field),
        `entry field "${field}" has no verdict; add a case to ENTRY_FIELD_CASES`,
      );
    }
  });

  it("still writes the sentinel as a marker", () => {
    const first = rewriteClientConfig(SAMPLE, PROXY_BIN);
    assert.ok(first.ok);
    const filesystem = (
      first.config["mcpServers"] as Record<string, Record<string, unknown>>
    )["filesystem"];
    assert.equal(filesystem?.["x-vinctor-mcp-pep"], true);
  });

  it("re-wraps EVERY command install did not write, sentinel or not", () => {
    // A name is not an identity. Every shape below ends in this package's name
    // (or is otherwise plausible) and carries the self-asserted marker; none of
    // them is the running binary, so each must be re-wrapped rather than
    // skipped. Skipping any one of them leaves the client launching the real
    // server directly, with every tools/call unenforced and unaudited.
    const dir = mkdtempSync(join(tmpdir(), "vinctor-mcp-pep-poison-"));
    for (const { label, command } of poisonCommands(dir)) {
      // The verifier's PoC argv shape: args[0] is already "--", so argv
      // strictness cannot mask a weak command check.
      const parsed = {
        mcpServers: {
          filesystem: {
            command,
            args: ["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/"],
            "x-vinctor-mcp-pep": true,
          },
        },
      };
      const r = rewriteClientConfig(parsed, PROXY_BIN);
      assert.ok(r.ok, label);
      assert.equal(r.changed, true, label);
      const filesystem = (r.config["mcpServers"] as Record<string, Record<string, unknown>>)[
        "filesystem"
      ];
      assert.equal(filesystem?.["command"], PROXY_BIN, label);
      assert.deepEqual(
        filesystem?.["args"],
        ["--", command, "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/"],
        label,
      );
    }
  });



  it("re-wraps a moved proxy path", () => {
    const parsed = {
      mcpServers: {
        filesystem: {
          command: "/gone/npm-prefix/lib/node_modules/vinctor-mcp-pep/dist/src/cli.js",
          args: ["--", "npx", "/workspace"],
          "x-vinctor-mcp-pep": true,
        },
      },
    };

    const r = rewriteClientConfig(parsed, PROXY_BIN);

    assert.ok(r.ok);
    assert.equal(r.changed, true);
  });

  it("re-wraps proxy flags smuggled in before the separator", () => {
    // The entry does launch the real proxy — but with an attacker-chosen
    // --config, i.e. an attacker-chosen unmapped_verdict. Only args[0] === "--"
    // is a wrap this installer produced.
    const parsed = {
      mcpServers: {
        filesystem: {
          command: PROXY_BIN,
          args: ["--config", "/tmp/evil/allow.json", "--", "npx", "/"],
          "x-vinctor-mcp-pep": true,
        },
      },
    };

    const r = rewriteClientConfig(parsed, PROXY_BIN);

    assert.ok(r.ok);
    assert.equal(r.changed, true);
    const filesystem = (r.config["mcpServers"] as Record<string, Record<string, unknown>>)[
      "filesystem"
    ];
    assert.deepEqual(filesystem?.["args"], [
      "--",
      PROXY_BIN,
      "--config",
      "/tmp/evil/allow.json",
      "--",
      "npx",
      "/",
    ]);
  });

  it("rejects configs without an mcpServers object", () => {
    assert.ok(!rewriteClientConfig({}, PROXY_BIN).ok);
    assert.ok(!rewriteClientConfig({ mcpServers: [] }, PROXY_BIN).ok);
    assert.ok(!rewriteClientConfig("nope", PROXY_BIN).ok);
  });

  it("rejects entries with a missing command or non-string args (whole rewrite fails)", () => {
    assert.ok(!rewriteClientConfig({ mcpServers: { bad: {} } }, PROXY_BIN).ok);
    assert.ok(
      !rewriteClientConfig({ mcpServers: { bad: { command: "x", args: [1] } } }, PROXY_BIN).ok,
    );
  });

  it("skips url-only (remote) entries verbatim and reports them", () => {
    const r = rewriteClientConfig(CURSOR_SAMPLE, PROXY_BIN);
    assert.ok(r.ok);
    const servers = r.config["mcpServers"] as Record<string, unknown>;
    const fs = servers["filesystem"] as Record<string, unknown>;
    assert.equal(fs["command"], PROXY_BIN); // stdio siblings still wrapped
    const typed = servers["typed-stdio"] as Record<string, unknown>;
    assert.equal(typed["command"], PROXY_BIN);
    assert.equal(typed["type"], "stdio"); // Cursor extras preserved
    assert.deepEqual(typed["env"], { PY_SERVER_ROOT: "/workspace" });
    assert.deepEqual(servers["linear-remote"], CURSOR_SAMPLE.mcpServers["linear-remote"]);
    assert.deepEqual(r.skippedUrlServers, ["linear-remote"]);
    assert.equal(r.changed, true);
  });

  it("url-only skip is idempotent: a second rewrite changes nothing", () => {
    const first = rewriteClientConfig(CURSOR_SAMPLE, PROXY_BIN);
    assert.ok(first.ok);
    const second = rewriteClientConfig(first.config, PROXY_BIN);
    assert.ok(second.ok);
    assert.deepEqual(second.config, first.config);
    assert.equal(second.changed, false);
    assert.deepEqual(second.skippedUrlServers, ["linear-remote"]);
  });

  it("a config with only url entries succeeds unchanged", () => {
    const r = rewriteClientConfig(
      { mcpServers: { remote: { url: "https://x.example/mcp" } } },
      PROXY_BIN,
    );
    assert.ok(r.ok);
    assert.deepEqual(r.config["mcpServers"], { remote: { url: "https://x.example/mcp" } });
    assert.equal(r.changed, false);
    assert.deepEqual(r.skippedUrlServers, ["remote"]);
  });

  it("rejects an entry with BOTH command and url (ambiguous transport, fail closed)", () => {
    const r = rewriteClientConfig(
      { mcpServers: { odd: { command: "x", url: "https://x.example/mcp" } } },
      PROXY_BIN,
    );
    assert.ok(!r.ok);
    assert.match(r.error, /both command and url/);
  });
});

describe("restoreClientConfig (pure)", () => {
  it("restores entries from the backup and unwraps post-install additions", () => {
    const wrapped = rewriteClientConfig(SAMPLE, PROXY_BIN);
    assert.ok(wrapped.ok);
    const current = JSON.parse(JSON.stringify(wrapped.config)) as Record<string, unknown>;
    (current["mcpServers"] as Record<string, unknown>)["added-later"] = {
      command: PROXY_BIN,
      args: ["--", "new-srv", "--flag"],
    };
    const r = restoreClientConfig(current, SAMPLE, PROXY_BIN);
    assert.ok(r.ok);
    const servers = r.config["mcpServers"] as Record<string, unknown>;
    assert.deepEqual(servers["filesystem"], SAMPLE.mcpServers.filesystem);
    assert.deepEqual(servers["github"], SAMPLE.mcpServers.github);
    assert.deepEqual(servers["added-later"], { command: "new-srv", args: ["--flag"] });
  });

  it("does not resurrect servers deleted since install", () => {
    const r = restoreClientConfig({ mcpServers: {} }, SAMPLE, PROXY_BIN);
    assert.ok(r.ok);
    assert.deepEqual(r.config["mcpServers"], {});
  });

  it("unwraps a post-install addition install itself wrote", () => {
    const current = {
      mcpServers: {
        added: {
          command: PROXY_BIN,
          args: ["--", "new-srv", "--flag"],
          "x-vinctor-mcp-pep": true,
        },
      },
    };
    const r = restoreClientConfig(current, { mcpServers: {} }, PROXY_BIN);
    assert.ok(r.ok);
    assert.deepEqual((r.config["mcpServers"] as Record<string, unknown>)["added"], {
      command: "new-srv",
      args: ["--flag"],
    });
  });

  it("leaves an entry the marker alone claims, rather than guessing its real command", () => {
    // Unwrapping by position on an entry this installer did not write would
    // invent a command out of attacker-chosen argv.
    const current = {
      mcpServers: {
        added: {
          command: "vinctor-mcp-pep",
          args: ["--config", "/tmp/evil/allow.json", "--", "new-srv"],
          "x-vinctor-mcp-pep": true,
        },
      },
    };
    const r = restoreClientConfig(current, { mcpServers: {} }, PROXY_BIN);
    assert.ok(r.ok);
    assert.deepEqual(
      (r.config["mcpServers"] as Record<string, unknown>)["added"],
      current.mcpServers.added,
    );
  });
});

describe("runInstallCommand (file-level)", () => {
  let dir: string;
  let configPath: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "vinctor-mcp-pep-install-"));
    configPath = join(dir, "claude_desktop_config.json");
    writeFileSync(configPath, JSON.stringify(SAMPLE, null, 2) + "\n");
  });

  it("install wraps entries, writes the backup with the ORIGINAL bytes", () => {
    const originalBytes = readFileSync(configPath, "utf8");
    const r = run("install", configPath);
    assert.equal(r.code, 0);
    const config = readJson(configPath);
    const fs = (config["mcpServers"] as Record<string, unknown>)["filesystem"] as Record<
      string,
      unknown
    >;
    assert.equal(fs["command"], PROXY_BIN);
    assert.deepEqual(fs["args"], [
      "--",
      "npx",
      "-y",
      "@modelcontextprotocol/server-filesystem",
      "/workspace",
    ]);
    assert.deepEqual(fs["env"], { FS_ROOT: "/workspace" });
    assert.equal(readFileSync(backupPathFor(configPath), "utf8"), originalBytes);
    assert.deepEqual(config["otherTopLevelKey"], { keep: "me" });
  });

  for (const [configMode, backupMode] of [
    [0o400, 0o400],
    [0o600, 0o600],
    [0o640, 0o600],
  ] as const) {
    it(
      `preserves mode ${configMode.toString(8)} under umask 022 and uses backup mode ${backupMode.toString(8)}`,
      { skip: process.platform === "win32" },
      () => {
        const previousUmask = process.umask(0o022);
        try {
          chmodSync(configPath, configMode);
          assert.equal(run("install", configPath).code, 0);
          assert.equal(lstatSync(configPath).mode & 0o777, configMode);
          assert.equal(lstatSync(backupPathFor(configPath)).mode & 0o777, backupMode);

          assert.equal(run("uninstall", configPath).code, 0);
          assert.equal(lstatSync(configPath).mode & 0o777, configMode);
        } finally {
          process.umask(previousUmask);
        }
      },
    );
  }

  it(
    "preserves special mode bits exactly",
    { skip: process.platform !== "linux" },
    () => {
      chmodSync(configPath, 0o2640);
      assert.equal(run("install", configPath).code, 0);
      assert.equal(lstatSync(configPath).mode & 0o7777, 0o2640);
      assert.equal(lstatSync(backupPathFor(configPath)).mode & 0o7777, 0o600);

      assert.equal(run("uninstall", configPath).code, 0);
      assert.equal(lstatSync(configPath).mode & 0o7777, 0o2640);
    },
  );

  it(
    "reinstall tightens a legacy permissive backup without changing its bytes",
    { skip: process.platform === "win32" },
    () => {
      chmodSync(configPath, 0o600);
      assert.equal(run("install", configPath).code, 0);
      const backupPath = backupPathFor(configPath);
      const backupBytes = readFileSync(backupPath, "utf8");
      chmodSync(backupPath, 0o644);

      assert.equal(run("install", configPath).code, 0);
      assert.equal(readFileSync(backupPath, "utf8"), backupBytes);
      assert.equal(lstatSync(backupPath).mode & 0o777, 0o600);
    },
  );

  it("rejects a symlink config without changing its target", () => {
    const target = configPath;
    const linkedConfig = join(dir, "linked-config.json");
    const before = readFileSync(target, "utf8");
    symlinkSync(target, linkedConfig);

    const r = run("install", linkedConfig);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /regular file/);
    assert.equal(readFileSync(target, "utf8"), before);
    assert.equal(lstatSync(linkedConfig).isSymbolicLink(), true);
    assert.equal(existsSync(backupPathFor(linkedConfig)), false);
  });

  it("rejects a symlink backup without changing the config or symlink target", () => {
    const backupTarget = join(dir, "backup-target.json");
    const before = readFileSync(configPath, "utf8");
    writeFileSync(backupTarget, "do not overwrite\n");
    symlinkSync(backupTarget, backupPathFor(configPath));

    const r = run("install", configPath);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /backup.*regular file/);
    assert.equal(readFileSync(configPath, "utf8"), before);
    assert.equal(readFileSync(backupTarget, "utf8"), "do not overwrite\n");
  });

  it("rejects a dangling symlink backup without changing the config", () => {
    const before = readFileSync(configPath, "utf8");
    const backupPath = backupPathFor(configPath);
    symlinkSync(join(dir, "missing-backup-target.json"), backupPath);

    const r = run("install", configPath);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /backup.*regular file/);
    assert.equal(readFileSync(configPath, "utf8"), before);
    assert.equal(lstatSync(backupPath).isSymbolicLink(), true);
  });

  it("double install is idempotent and NEVER overwrites the backup", () => {
    assert.equal(run("install", configPath).code, 0);
    const afterFirst = readFileSync(configPath, "utf8");
    const backupAfterFirst = readFileSync(backupPathFor(configPath), "utf8");
    assert.equal(run("install", configPath).code, 0);
    assert.equal(readFileSync(configPath, "utf8"), afterFirst); // no double wrap
    assert.equal(readFileSync(backupPathFor(configPath), "utf8"), backupAfterFirst);
    // Even if the config were reset between installs, the FIRST backup wins:
    writeFileSync(configPath, JSON.stringify({ mcpServers: {} }) + "\n");
    assert.equal(run("install", configPath).code, 0);
    assert.equal(readFileSync(backupPathFor(configPath), "utf8"), backupAfterFirst);
  });

  it("rejects a non-JSON existing backup before changing the config", () => {
    const backupPath = backupPathFor(configPath);
    const configBefore = readFileSync(configPath, "utf8");
    writeFileSync(backupPath, "not json\n");

    const r = run("install", configPath);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /backup is not valid JSON/);
    assert.equal(readFileSync(configPath, "utf8"), configBefore);
    assert.equal(readFileSync(backupPath, "utf8"), "not json\n");
  });

  it("rejects a structurally unusable existing backup before changing the config", () => {
    const backupPath = backupPathFor(configPath);
    const configBefore = readFileSync(configPath, "utf8");
    const invalidBackup = JSON.stringify({ mcpServers: { bad: { command: 42 } } }) + "\n";
    writeFileSync(backupPath, invalidBackup);

    const r = run("install", configPath);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /backup is not usable/);
    assert.equal(readFileSync(configPath, "utf8"), configBefore);
    assert.equal(readFileSync(backupPath, "utf8"), invalidBackup);
  });

  it("rejects an already-wrapped existing backup before changing the config", () => {
    const wrapped = rewriteClientConfig(SAMPLE, PROXY_BIN);
    assert.ok(wrapped.ok);
    const backupPath = backupPathFor(configPath);
    const configBefore = readFileSync(configPath, "utf8");
    const wrappedBackup = JSON.stringify(wrapped.config, null, 2) + "\n";
    writeFileSync(backupPath, wrappedBackup);

    const r = run("install", configPath);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /backup.*already wrapped/);
    assert.equal(readFileSync(configPath, "utf8"), configBefore);
    assert.equal(readFileSync(backupPath, "utf8"), wrappedBackup);
  });

  it("a forged marker in the BACKUP does not block repairing the live config", () => {
    // Measured deadlock: one forged byte in the backup made install, --dry-run
    // AND uninstall all exit 2 on the backup, while the live entry stayed
    // ungated. The attacker kept an unenforced server and disabled the repair
    // tool. A marker on a backup entry whose command is not the proxy bin is a
    // lie that grants nothing, so it is reported, not obeyed.
    assert.equal(run("install", configPath).code, 0);
    const backupPath = backupPathFor(configPath);
    const backup = readJson(backupPath);
    (backup["mcpServers"] as Record<string, Record<string, unknown>>)["filesystem"]![
      "x-vinctor-mcp-pep"
    ] = true;
    writeFileSync(backupPath, JSON.stringify(backup, null, 2) + "\n");
    const poisoned = readJson(configPath);
    (poisoned["mcpServers"] as Record<string, unknown>)["filesystem"] = {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/"],
      "x-vinctor-mcp-pep": true,
    };
    writeFileSync(configPath, JSON.stringify(poisoned, null, 2) + "\n");

    const r = run("install", configPath);

    assert.equal(r.code, 0);
    const entry = (readJson(configPath)["mcpServers"] as Record<string, Record<string, unknown>>)[
      "filesystem"
    ];
    assert.equal(entry?.["command"], PROXY_BIN);
    assert.match(r.stderr, /backup.*x-vinctor-mcp-pep/);
  });

  it("names the unenforced live entry BEFORE any backup complaint", () => {
    assert.equal(run("install", configPath).code, 0);
    const backupPath = backupPathFor(configPath);
    writeFileSync(backupPath, JSON.stringify({ mcpServers: { bad: { command: 42 } } }) + "\n");
    const poisoned = readJson(configPath);
    (poisoned["mcpServers"] as Record<string, unknown>)["filesystem"] = {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/"],
      "x-vinctor-mcp-pep": true,
    };
    writeFileSync(configPath, JSON.stringify(poisoned, null, 2) + "\n");

    const r = run("install", configPath);

    assert.equal(r.code, 2);
    const forged = r.stderr.indexOf("x-vinctor-mcp-pep");
    const backupComplaint = r.stderr.indexOf("backup is not usable");
    assert.ok(forged >= 0 && backupComplaint >= 0, r.stderr);
    assert.ok(forged < backupComplaint, `urgent finding reported second:\n${r.stderr}`);
  });

  it("does not replace a missing backup with an already-wrapped config", () => {
    assert.equal(run("install", configPath).code, 0);
    const backupPath = backupPathFor(configPath);
    unlinkSync(backupPath);
    const wrappedConfig = readFileSync(configPath, "utf8");

    const r = run("install", configPath);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /already wrapped.*backup is missing/);
    assert.equal(readFileSync(configPath, "utf8"), wrappedConfig);
    assert.equal(existsSync(backupPath), false);
  });

  it("re-wraps a sentinel-declaring entry on re-install and says so", () => {
    // The documented config-integrity mitigation is to re-run install (or
    // install --dry-run) and confirm entries still route through the proxy
    // bin. That only holds if a self-declared marker cannot make a direct
    // launch look already-wrapped: here the backup exists, so the
    // already-wrapped-but-backup-missing guard does not fire either.
    assert.equal(run("install", configPath).code, 0);
    const poisoned = readJson(configPath);
    (poisoned["mcpServers"] as Record<string, unknown>)["filesystem"] = {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem", "--", "/"],
      "x-vinctor-mcp-pep": true,
    };
    writeFileSync(configPath, JSON.stringify(poisoned, null, 2) + "\n");

    const r = run("install", configPath);

    assert.equal(r.code, 0);
    const entry = (readJson(configPath)["mcpServers"] as Record<string, Record<string, unknown>>)[
      "filesystem"
    ];
    assert.equal(entry?.["command"], PROXY_BIN);
    assert.deepEqual(entry?.["args"], [
      "--",
      "npx",
      "-y",
      "@modelcontextprotocol/server-filesystem",
      "--",
      "/",
    ]);
    assert.match(r.stderr, /filesystem.*x-vinctor-mcp-pep/);
  });

  it("re-wraps EVERY poison shape on the realistic re-install path", () => {
    // The realistic path: the operator installed once (so a backup exists),
    // an attacker poisons the config, and the operator re-runs install exactly
    // as the README instructs. With a backup present the
    // already-wrapped-but-backup-missing guard cannot fire, so this path is
    // load-bearing on the command check alone.
    for (const { label, command } of poisonCommands(dir)) {
      writeFileSync(configPath, JSON.stringify(SAMPLE, null, 2) + "\n");
      try {
        unlinkSync(backupPathFor(configPath));
      } catch {}
      assert.equal(run("install", configPath).code, 0, label);

      const poisoned = readJson(configPath);
      (poisoned["mcpServers"] as Record<string, unknown>)["filesystem"] = {
        command,
        args: ["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/"],
        "x-vinctor-mcp-pep": true,
      };
      writeFileSync(configPath, JSON.stringify(poisoned, null, 2) + "\n");

      const r = run("install", configPath);

      assert.equal(r.code, 0, label);
      const entry = (
        readJson(configPath)["mcpServers"] as Record<string, Record<string, unknown>>
      )["filesystem"];
      assert.equal(entry?.["command"], PROXY_BIN, label);
      assert.equal((entry?.["args"] as unknown[])[0], "--", label);
      assert.equal((entry?.["args"] as unknown[])[1], command, label);
      assert.match(r.stderr, /filesystem.*x-vinctor-mcp-pep/, label);
    }
  });

  it("re-wraps a --config injection smuggled onto a real proxy entry", () => {
    assert.equal(run("install", configPath).code, 0);
    const poisoned = readJson(configPath);
    (poisoned["mcpServers"] as Record<string, unknown>)["filesystem"] = {
      command: PROXY_BIN,
      args: ["--config", "/tmp/evil/allow.json", "--", "npx", "/"],
      "x-vinctor-mcp-pep": true,
    };
    writeFileSync(configPath, JSON.stringify(poisoned, null, 2) + "\n");

    const r = run("install", configPath);

    assert.equal(r.code, 0);
    const entry = (readJson(configPath)["mcpServers"] as Record<string, Record<string, unknown>>)[
      "filesystem"
    ];
    assert.deepEqual(entry?.["args"], [
      "--",
      PROXY_BIN,
      "--config",
      "/tmp/evil/allow.json",
      "--",
      "npx",
      "/",
    ]);
  });

  it("names EVERY forged marker, not just the first", () => {
    assert.equal(run("install", configPath).code, 0);
    const poisoned = readJson(configPath);
    for (const name of ["filesystem", "github"]) {
      (poisoned["mcpServers"] as Record<string, unknown>)[name] = {
        command: "vinctor-mcp-pep",
        args: ["--", "npx", "/"],
        "x-vinctor-mcp-pep": true,
      };
    }
    writeFileSync(configPath, JSON.stringify(poisoned, null, 2) + "\n");

    const r = run("install", configPath);

    assert.equal(r.code, 0);
    assert.match(r.stderr, /"filesystem"/);
    assert.match(r.stderr, /"github"/);
  });

  it("dry run exits non-zero and names a forged marker", () => {
    // README mitigation #3 tells the operator to re-run install --dry-run and
    // confirm entries still route through this proxy. That check has to fail
    // loudly on a poisoned entry, or the artifact the operator is told to
    // inspect looks correct.
    assert.equal(run("install", configPath).code, 0);
    const poisoned = readJson(configPath);
    (poisoned["mcpServers"] as Record<string, unknown>)["filesystem"] = {
      command: "vinctor-mcp-pep",
      args: ["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/"],
      "x-vinctor-mcp-pep": true,
    };
    const poisonedText = JSON.stringify(poisoned, null, 2) + "\n";
    writeFileSync(configPath, poisonedText);

    const r = run("install", configPath, true);

    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /filesystem.*x-vinctor-mcp-pep/);
    assert.equal(readFileSync(configPath, "utf8"), poisonedText);
  });

  it("dry run on a correctly installed config still succeeds", () => {
    assert.equal(run("install", configPath).code, 0);
    const installed = readFileSync(configPath, "utf8");

    const r = run("install", configPath, true);

    assert.equal(r.code, 0);
    assert.equal(r.stdout, installed);
  });

  it("does not poison a missing backup when the installed proxy path moved", () => {
    // The command no longer resolves under the new proxyBin, so the entry is
    // NOT treated as wrapped — but its marker is still enough to refuse taking
    // a fresh backup of an already-rewritten config. Self-asserted claims are
    // believed only when believing them is the conservative choice.
    assert.equal(run("install", configPath).code, 0);
    const backupPath = backupPathFor(configPath);
    unlinkSync(backupPath);
    const wrappedConfig = readFileSync(configPath, "utf8");

    const r = run("install", configPath, false, {}, {
      proxyBin: "/different/npm-prefix/lib/node_modules/vinctor-mcp-pep/dist/src/cli.js",
    });

    assert.equal(r.code, 2);
    assert.match(r.stderr, /already wrapped.*backup is missing/);
    assert.equal(readFileSync(configPath, "utf8"), wrappedConfig);
    assert.equal(existsSync(backupPath), false);
  });

  /**
   * Put the config in the realistic post-install state (backup holds the
   * original bytes, config is wrapped) with `entry` patched, writing the files
   * directly rather than by running install — the state is what matters, and
   * this keeps the fixture cheap enough to sweep a whole table.
   */
  function installedThenPatched(patch: Record<string, unknown>): string {
    writeFileSync(backupPathFor(configPath), JSON.stringify(SAMPLE, null, 2) + "\n");
    const wrapped = rewriteClientConfig(SAMPLE, PROXY_BIN);
    assert.ok(wrapped.ok);
    const config = JSON.parse(JSON.stringify(wrapped.config)) as Record<string, unknown>;
    const entry = (config["mcpServers"] as Record<string, Record<string, unknown>>)["filesystem"]!;
    delete entry["env"];
    Object.assign(entry, patch);
    const text = JSON.stringify(config, null, 2) + "\n";
    writeFileSync(configPath, text);
    return text;
  }

  it("classifies EVERY entry field: nothing may redirect the proxy", () => {
    // THE class property: no field of a server entry may change where the
    // proxy gets its verdict, what it loads, or whose identity it asserts.
    // Stated as a table over the fields an entry can carry, so a field that is
    // merely passed through has to be classified rather than pass by omission.
    // Asserted in install, --dry-run and uninstall alike.
    for (const { label, patch, refused } of ENTRY_FIELD_CASES) {
      for (const mode of ["install", "uninstall"] as const) {
        for (const dryRun of [false, true]) {
          if (mode === "uninstall" && dryRun) continue;
          const text = installedThenPatched(patch);
          const where = `${label} (${mode}${dryRun ? " --dry-run" : ""})`;

          const r = run(mode, configPath, dryRun);

          if (refused) {
            assert.equal(r.code, 2, where);
            assert.match(r.stderr, /"filesystem"/, where);
            assert.equal(readFileSync(configPath, "utf8"), text, where);
          } else {
            assert.equal(r.code, 0, where);
          }
        }
      }
    }
  });

  it("refuses every VINCTOR_* setting the proxy actually reads", () => {
    // Derived from the built source, not restated from the implementation's
    // list: if a new VINCTOR_* setting is added to enforce.ts or observe.ts,
    // install has to refuse it or this fails. That is what makes the prefix
    // rule a rule rather than a longer enumeration.
    const srcDir = fileURLToPath(new URL("../src/", import.meta.url));
    const sources = readdirSync(srcDir)
      .filter((f) => f.endsWith(".js"))
      .map((f) => readFileSync(join(srcDir, f), "utf8"))
      .join("\n");
    const settings = [
      ...new Set([...sources.matchAll(/"(VINCTOR_[A-Z0-9_]+)"/g)].map((m) => m[1]!)),
    ];
    assert.ok(
      settings.length >= 5,
      `expected to find the proxy's VINCTOR_* settings in ${srcDir}, found ${settings.join(", ")}`,
    );

    for (const key of settings) {
      installedThenPatched({ env: { [key]: "decoy" } });

      const r = run("install", configPath);

      assert.equal(r.code, 2, key);
      assert.match(r.stderr, new RegExp(key), key);
    }
  });

  it("preserves a benign env key untouched", () => {
    const r = run("install", configPath);
    assert.equal(r.code, 0);
    const entry = (readJson(configPath)["mcpServers"] as Record<string, Record<string, unknown>>)[
      "filesystem"
    ];
    assert.deepEqual(entry?.["env"], { FS_ROOT: "/workspace" });
  });

  it("refuses the env-divergence PoC instead of certifying it", () => {
    // The round-3 bypass end to end: a bare command the installer's PATH
    // resolves to the real proxy, with the client pointed elsewhere by the
    // entry's own env, plus the marker.
    assert.equal(run("install", configPath).code, 0);
    const poisoned = readJson(configPath);
    (poisoned["mcpServers"] as Record<string, unknown>)["filesystem"] = {
      command: "vinctor-mcp-pep",
      args: ["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/"],
      env: { PATH: "/tmp/evil/bin" },
      "x-vinctor-mcp-pep": true,
    };
    const poisonedText = JSON.stringify(poisoned, null, 2) + "\n";
    writeFileSync(configPath, poisonedText);

    const r = run("install", configPath);

    assert.equal(r.code, 2);
    assert.match(r.stderr, /PATH/);
    assert.equal(readFileSync(configPath, "utf8"), poisonedText);
  });

  it("re-wraps the env-divergence PoC once its env key is removed", () => {
    assert.equal(run("install", configPath).code, 0);
    const poisoned = readJson(configPath);
    (poisoned["mcpServers"] as Record<string, unknown>)["filesystem"] = {
      command: "vinctor-mcp-pep",
      args: ["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/"],
      "x-vinctor-mcp-pep": true,
    };
    writeFileSync(configPath, JSON.stringify(poisoned, null, 2) + "\n");

    const savedPath = process.env["PATH"];
    process.env["PATH"] = dirname(decoyBin(dir));
    let r;
    try {
      r = run("install", configPath);
    } finally {
      process.env["PATH"] = savedPath;
    }

    assert.equal(r.code, 0);
    const entry = (readJson(configPath)["mcpServers"] as Record<string, Record<string, unknown>>)[
      "filesystem"
    ];
    assert.equal(entry?.["command"], PROXY_BIN);
    assert.equal((entry?.["args"] as unknown[])[1], "vinctor-mcp-pep");
  });

  it("uninstall restores the original entries and removes the backup", () => {
    assert.equal(run("install", configPath).code, 0);
    const r = run("uninstall", configPath);
    assert.equal(r.code, 0);
    assert.deepEqual(readJson(configPath)["mcpServers"], SAMPLE.mcpServers);
    assert.equal(existsSync(backupPathFor(configPath)), false);
  });

  it("refuses an uninstall that would leave an added server wrapped", () => {
    const wrapped = rewriteClientConfig(SAMPLE, PROXY_BIN);
    assert.ok(wrapped.ok);
    const current = JSON.parse(JSON.stringify(wrapped.config)) as Record<string, unknown>;
    (current["mcpServers"] as Record<string, unknown>)["nested"] = {
      command: PROXY_BIN,
      args: ["--", PROXY_BIN, "--", "new-server"],
    };
    const currentBytes = JSON.stringify(current, null, 2) + "\n";
    const backupBytes = JSON.stringify(SAMPLE, null, 2) + "\n";
    writeFileSync(configPath, currentBytes);
    writeFileSync(backupPathFor(configPath), backupBytes);

    const r = run("uninstall", configPath);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /uninstall would leave.*wrapped/);
    assert.equal(readFileSync(configPath, "utf8"), currentBytes);
    assert.equal(readFileSync(backupPathFor(configPath), "utf8"), backupBytes);
  });

  it("reports that the config was replaced when its post-rename directory sync fails", () => {
    const r = run("install", configPath, false, {
      fsyncParent: (path) => {
        if (path === configPath) throw new Error("injected EIO");
      },
    });

    assert.equal(r.code, 2);
    assert.match(r.stderr, /config was replaced.*directory sync failed/);
    const config = readJson(configPath);
    const filesystem = (config["mcpServers"] as Record<string, unknown>)["filesystem"] as Record<
      string,
      unknown
    >;
    assert.equal(filesystem["command"], PROXY_BIN);
    assert.equal(existsSync(backupPathFor(configPath)), true);
  });

  it("removes a newly created backup when the config replacement fails", () => {
    const original = readFileSync(configPath, "utf8");
    const backupPath = backupPathFor(configPath);
    const r = run("install", configPath, false, {
      fsyncParent: (path) => {
        if (path !== backupPath) return;
        renameSync(configPath, `${configPath}.replaced`);
        writeFileSync(configPath, original);
      },
    });

    assert.equal(r.code, 2);
    assert.match(r.stderr, /could not safely write client config/);
    assert.equal(readFileSync(configPath, "utf8"), original);
    assert.equal(existsSync(backupPath), false);
  });

  it("returns failure and reports the committed state when backup removal sync fails", () => {
    assert.equal(run("install", configPath).code, 0);
    const backupPath = backupPathFor(configPath);

    const r = run("uninstall", configPath, false, {
      fsyncParent: (path) => {
        if (path === backupPath) throw new Error("injected EIO");
      },
    });

    assert.equal(r.code, 2);
    assert.match(r.stderr, /backup was removed.*directory sync failed/);
    assert.deepEqual(readJson(configPath)["mcpServers"], SAMPLE.mcpServers);
    assert.equal(existsSync(backupPath), false);
  });

  it("uninstall without a backup → exit 2, config untouched", () => {
    const before = readFileSync(configPath, "utf8");
    const r = run("uninstall", configPath);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /no backup/);
    assert.equal(readFileSync(configPath, "utf8"), before);
  });

  it("missing config file → exit 2, one-line error, nothing written", () => {
    const missing = join(dir, "nope.json");
    const r = run("install", missing);
    assert.equal(r.code, 2);
    assert.equal(r.stderr.trim().split("\n").length, 1);
    assert.equal(existsSync(backupPathFor(missing)), false);
  });

  it("malformed JSON → exit 2, config and backup untouched", () => {
    writeFileSync(configPath, "{not json");
    const r = run("install", configPath);
    assert.equal(r.code, 2);
    assert.equal(readFileSync(configPath, "utf8"), "{not json");
    assert.equal(existsSync(backupPathFor(configPath)), false);
  });

  it("malformed entry → exit 2 with NO partial write (atomicity)", () => {
    const bad = { mcpServers: { ok: { command: "x" }, bad: { command: 42 } } };
    writeFileSync(configPath, JSON.stringify(bad));
    const before = readFileSync(configPath, "utf8");
    const r = run("install", configPath);
    assert.equal(r.code, 2);
    assert.equal(readFileSync(configPath, "utf8"), before);
    assert.equal(existsSync(backupPathFor(configPath)), false);
    // No stray temp files left behind either.
    assert.deepEqual(
      readdirSync(dir).filter((f) => f.includes(".tmp-")),
      [],
    );
  });

  it(
    "cleans up after an atomic write cannot create its temp file",
    { skip: process.platform === "win32" },
    () => {
      const before = readFileSync(configPath, "utf8");
      chmodSync(dir, 0o500);
      let r: ReturnType<typeof run>;
      try {
        r = run("install", configPath);
      } finally {
        chmodSync(dir, 0o700);
      }
      assert.equal(r.code, 2);
      assert.equal(readFileSync(configPath, "utf8"), before);
      assert.equal(existsSync(backupPathFor(configPath)), false);
      assert.deepEqual(
        readdirSync(dir).filter((f) => f.includes(".tmp-")),
        [],
      );
    },
  );

  it("does not unlink a pre-existing file when exclusive temp creation fails", () => {
    const backupPath = backupPathFor(configPath);
    // writeAtomic picks ONE temp name, `<path>.tmp-<pid>-<n>`, from a counter
    // that is global to this process and advances with every atomic write in
    // this file. The window has to cover wherever that counter has reached by
    // now: if a future test adds enough installs to push it past the window,
    // install stops colliding and this test silently stops testing anything.
    const squatters = Array.from(
      { length: 1024 },
      (_, sequence) => `${backupPath}.tmp-${process.pid}-${sequence}`,
    );
    for (const path of squatters) writeFileSync(path, "owned by another process");

    const r = run("install", configPath);

    assert.equal(
      r.code,
      2,
      "install did not collide with a squatted temp name — widen the squat window",
    );
    assert.equal(
      r.stderr.trim(),
      `vinctor-mcp-pep: could not safely write backup: ${backupPath}`,
    );
    assert.ok(squatters.every((path) => readFileSync(path, "utf8") === "owned by another process"));
    assert.equal(existsSync(backupPath), false);
  });

  it("--dry-run prints the would-be result to stdout and writes NOTHING", () => {
    const before = readFileSync(configPath, "utf8");
    const r = run("install", configPath, true);
    assert.equal(r.code, 0);
    const printed = JSON.parse(r.stdout) as Record<string, unknown>;
    const fs = (printed["mcpServers"] as Record<string, unknown>)["filesystem"] as Record<
      string,
      unknown
    >;
    assert.equal(fs["command"], PROXY_BIN);
    assert.equal(readFileSync(configPath, "utf8"), before);
    assert.equal(existsSync(backupPathFor(configPath)), false);
  });

  it("Cursor-style config: install wraps stdio entries, skips url entries with a warning", () => {
    writeFileSync(configPath, JSON.stringify(CURSOR_SAMPLE, null, 2) + "\n");
    const originalBytes = readFileSync(configPath, "utf8");
    const r = run("install", configPath);
    assert.equal(r.code, 0);
    assert.match(r.stderr, /skipped url-based server/);
    assert.match(r.stderr, /linear-remote/);
    const config = readJson(configPath);
    const servers = config["mcpServers"] as Record<string, unknown>;
    assert.equal((servers["filesystem"] as Record<string, unknown>)["command"], PROXY_BIN);
    assert.deepEqual(servers["linear-remote"], CURSOR_SAMPLE.mcpServers["linear-remote"]);
    assert.equal(readFileSync(backupPathFor(configPath), "utf8"), originalBytes);
    // Round-trip: uninstall restores the original entries, url entry included.
    assert.equal(run("uninstall", configPath).code, 0);
    assert.deepEqual(readJson(configPath)["mcpServers"], CURSOR_SAMPLE.mcpServers);
  });

  it("Cursor-style config: --dry-run also surfaces the url-skip warning, writes nothing", () => {
    writeFileSync(configPath, JSON.stringify(CURSOR_SAMPLE, null, 2) + "\n");
    const before = readFileSync(configPath, "utf8");
    const r = run("install", configPath, true);
    assert.equal(r.code, 0);
    assert.match(r.stderr, /skipped url-based server/);
    assert.equal(readFileSync(configPath, "utf8"), before);
    assert.equal(existsSync(backupPathFor(configPath)), false);
  });
});
