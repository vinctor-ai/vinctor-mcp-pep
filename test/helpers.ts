import {
  accessSync,
  constants,
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { startProxy, type RunningProxy, type ProxyOptions } from "../src/proxy.js";

// Mock MCP server, written to a temp file and spawned BY THE PROXY as its child
// (the real topology). It appends every received line to a log file, replies to
// every request (a message with an id) with a deterministic result that echoes
// the method AND the raw bytes it received, and announces itself on stderr.
const MOCK_SERVER_SRC = [
  'const fs = require("node:fs");',
  "const logPath = process.argv[2];",
  'fs.writeFileSync(logPath, "");',
  "let serverRequestIds = [];",
  "try { serverRequestIds = JSON.parse(process.env.MOCK_SERVER_REQUEST_IDS ?? \"[]\"); } catch {}",
  "let serverRequests = [];",
  "try { serverRequests = JSON.parse(process.env.MOCK_SERVER_REQUESTS ?? \"[]\"); } catch {}",
  "let signaledServerMessages = [];",
  "try { signaledServerMessages = JSON.parse(process.env.MOCK_SERVER_SIGNAL_MESSAGES ?? \"[]\"); } catch {}",
  "let heldRequestIds = [];",
  "try { heldRequestIds = JSON.parse(process.env.MOCK_SERVER_HOLD_IDS ?? \"[]\"); } catch {}",
  "const heldRequestKeys = new Set(heldRequestIds.map((id) => `${typeof id}:${String(id)}`));",
  "for (const id of serverRequestIds) {",
  "  if (typeof id !== \"string\" && !Number.isInteger(id)) continue;",
  "  const request = { jsonrpc: \"2.0\", id, method: \"roots/list\" };",
  '  process.stdout.write(JSON.stringify(request) + "\\n");',
  "}",
  "function writeServerMessages(messages) {",
  "  for (const message of messages) {",
  "    if (message === null || typeof message !== \"object\" || Array.isArray(message)) continue;",
  '    process.stdout.write(JSON.stringify(message) + "\\n");',
  "  }",
  "}",
  'process.on("SIGUSR2", () => writeServerMessages(signaledServerMessages));',
  'process.stderr.write("mock-mcp-server started\\n");',
  "writeServerMessages(serverRequests);",
  'const stallStdin = process.env.MOCK_SERVER_STALL_STDIN === "1";',
  'const keepAliveAfterStdin = process.env.MOCK_SERVER_KEEP_ALIVE_AFTER_STDIN === "1";',
  "let readingStarted = false;",
  "let keepAlive = stallStdin || keepAliveAfterStdin ? setInterval(() => {}, 1000) : null;",
  "function startReading() {",
  "  if (readingStarted) return;",
  "  readingStarted = true;",
  "  if (keepAlive !== null && !keepAliveAfterStdin) { clearInterval(keepAlive); keepAlive = null; }",
  '  let buf = "";',
  '  process.stdin.setEncoding("utf8");',
  '  process.stdin.on("data", (c) => {',
  "    buf += c;",
  "    let nl;",
  '    while ((nl = buf.indexOf("\\n")) >= 0) {',
  "      const line = buf.slice(0, nl);",
  "      buf = buf.slice(nl + 1);",
  "      if (line.length === 0) continue;",
  '      fs.appendFileSync(logPath, line + "\\n");',
  "      let msg;",
  "      try { msg = JSON.parse(line); } catch { continue; }",
  "      if (msg === null || typeof msg !== \"object\" || Array.isArray(msg)) continue;",
  "      if (msg.id === undefined || msg.id === null) continue;",
  "      if (heldRequestKeys.has(`${typeof msg.id}:${String(msg.id)}`)) continue;",
  "      const res = {",
  '        jsonrpc: "2.0",',
  "        id: msg.id,",
  "        result: { echoMethod: msg.method, echoRaw: line },",
  "      };",
  '      process.stdout.write(JSON.stringify(res) + "\\n");',
  "    }",
  "  });",
  '  process.stdin.on("end", () => { if (!keepAliveAfterStdin) process.exit(0); });',
  "}",
  'if (stallStdin) process.on("SIGUSR1", startReading); else startReading();',
].join("\n");

function createMockServer(): { serverPath: string; logPath: string } {
  const dir = mkdtempSync(join(tmpdir(), "vinctor-mcp-pep-test-"));
  const serverPath = join(dir, "mock-mcp-server.cjs");
  const logPath = join(dir, "received.log");
  writeFileSync(serverPath, MOCK_SERVER_SRC);
  return { serverPath, logPath };
}

export type Harness = {
  proxy: RunningProxy;
  /** Write one line (newline appended) to the proxy's client stdin. */
  send: (line: string) => void;
  /** Write raw bytes with NO newline appended (for chunk-boundary tests). */
  sendRaw: (data: string | Buffer) => void;
  endInput: () => void;
  /** Complete lines the client has received from the proxy so far. */
  clientLines: string[];
  stderrText: () => string;
  pauseClientOutput: () => void;
  resumeClientOutput: () => void;
  clientOutputBufferedBytes: () => number;
  clientOutputHighWaterBytes: () => number;
  pauseClientError: () => void;
  resumeClientError: () => void;
  clientErrorBufferedBytes: () => number;
  clientErrorHighWaterBytes: () => number;
  resumeChildInput: () => void;
  closeChildInput: () => void;
  emitServerMessages: () => void;
  /** Raw lines the mock MCP server has received (from its log file). */
  serverLog: () => string[];
  stop: () => Promise<void>;
};

export function startHarness(
  env: Record<string, string | undefined>,
  overrides: Partial<
    Pick<ProxyOptions, "fetchFn" | "enforceTimeoutMs" | "maxLineBytes" | "unmappedVerdict">
  > = {},
): Harness {
  const { serverPath, logPath } = createMockServer();

  const clientIn = new PassThrough();
  const clientOut = new PassThrough();
  const clientErr = new PassThrough();

  const clientLines: string[] = [];
  let outBuf = "";
  clientOut.on("data", (c: Buffer) => {
    outBuf += c.toString("utf8");
    let nl: number;
    while ((nl = outBuf.indexOf("\n")) >= 0) {
      clientLines.push(outBuf.slice(0, nl));
      outBuf = outBuf.slice(nl + 1);
    }
  });
  let errBuf = "";
  clientErr.on("data", (c: Buffer) => {
    errBuf += c.toString("utf8");
  });

  const proxy = startProxy({
    command: process.execPath,
    args: [serverPath, logPath],
    clientIn,
    clientOut,
    clientErr,
    env,
    ...overrides,
  });

  return {
    proxy,
    send: (line) => void clientIn.write(line + "\n"),
    sendRaw: (data) => void clientIn.write(data),
    endInput: () => clientIn.end(),
    clientLines,
    stderrText: () => errBuf,
    pauseClientOutput: () => clientOut.pause(),
    resumeClientOutput: () => clientOut.resume(),
    clientOutputBufferedBytes: () => clientOut.readableLength + clientOut.writableLength,
    clientOutputHighWaterBytes: () =>
      clientOut.readableHighWaterMark + clientOut.writableHighWaterMark,
    pauseClientError: () => clientErr.pause(),
    resumeClientError: () => clientErr.resume(),
    clientErrorBufferedBytes: () => clientErr.readableLength + clientErr.writableLength,
    clientErrorHighWaterBytes: () =>
      clientErr.readableHighWaterMark + clientErr.writableHighWaterMark,
    resumeChildInput: () => {
      proxy.child.kill("SIGUSR1");
    },
    closeChildInput: () => {
      proxy.child.stdin.destroy();
    },
    emitServerMessages: () => {
      proxy.child.kill("SIGUSR2");
    },
    serverLog: () =>
      existsSync(logPath)
        ? readFileSync(logPath, "utf8").split("\n").filter((l) => l.length > 0)
        : [],
    stop: async () => {
      proxy.child.kill("SIGKILL");
      await proxy.done;
    },
  };
}

export type CliHarness = Pick<
  Harness,
  "send" | "clientLines" | "stderrText" | "serverLog" | "stop"
>;

/**
 * Resolve the npm-packed CLI used by real-core E2E. There is deliberately no
 * source fallback: a green E2E run must prove the packaged artifact.
 */
export function resolvePackagedProxyBin(
  env: Record<string, string | undefined> = process.env,
): string {
  const configured = env["VINCTOR_MCP_PEP_BIN"];
  if (!configured) {
    throw new Error(
      "real-service e2e requires VINCTOR_MCP_PEP_BIN pointing to an npm-packed install",
    );
  }
  let resolved: string;
  try {
    resolved = realpathSync(configured);
    accessSync(resolved, constants.X_OK);
  } catch {
    throw new Error(
      `real-service e2e requires an executable npm-packed proxy binary: ${configured}`,
    );
  }
  const sourceRoot = realpathSync(fileURLToPath(new URL("../..", import.meta.url)));
  const fromSource = relative(sourceRoot, resolved);
  if (fromSource === "" || (!fromSource.startsWith("..") && !isAbsolute(fromSource))) {
    throw new Error(
      `real-service e2e requires VINCTOR_MCP_PEP_BIN outside the source checkout: ${resolved}`,
    );
  }
  return resolved;
}

export function startCliHarness(env: Record<string, string | undefined>): CliHarness {
  const { serverPath, logPath } = createMockServer();
  const proxyBin = resolvePackagedProxyBin();
  const proxy = spawn(proxyBin, ["--", process.execPath, serverPath, logPath], {
    env: { ...process.env, ...env },
    stdio: ["pipe", "pipe", "pipe"],
  });

  const clientLines: string[] = [];
  let outBuf = "";
  proxy.stdout.on("data", (c: Buffer) => {
    outBuf += c.toString("utf8");
    let nl: number;
    while ((nl = outBuf.indexOf("\n")) >= 0) {
      clientLines.push(outBuf.slice(0, nl));
      outBuf = outBuf.slice(nl + 1);
    }
  });
  let errBuf = "";
  proxy.stderr.on("data", (c: Buffer) => {
    errBuf += c.toString("utf8");
  });
  const closed = new Promise<void>((resolve) => {
    proxy.once("close", () => resolve());
    proxy.once("error", () => resolve());
  });

  return {
    send: (line) => void proxy.stdin.write(line + "\n"),
    clientLines,
    stderrText: () => errBuf,
    serverLog: () =>
      existsSync(logPath)
        ? readFileSync(logPath, "utf8").split("\n").filter((l) => l.length > 0)
        : [],
    stop: async () => {
      if (!proxy.stdin.destroyed) proxy.stdin.end();
      const exited = await Promise.race([
        closed.then(() => true),
        new Promise<false>((resolve) => setTimeout(() => resolve(false), 2_000)),
      ]);
      if (!exited) {
        proxy.kill("SIGKILL");
        await closed;
      }
    },
  };
}

/** Poll until `cond` is true; fail loudly with `what` on timeout. */
export async function until(cond: () => boolean, what: string, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for: ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

/** A brief settle window for asserting that something did NOT happen. */
export async function settle(ms = 150): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}
