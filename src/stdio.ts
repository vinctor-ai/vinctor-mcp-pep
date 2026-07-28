import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { childEnv } from "./child_env.js";
import type { LineSplitter } from "./lines.js";
import {
  createServerRequestTracker,
  type ServerRequestTracker,
} from "./server_requests.js";

type TransportOptions = {
  readonly command: string;
  readonly args: string[];
  readonly env: Record<string, string | undefined>;
  readonly clientOut: Writable;
  readonly clientErr: Writable;
  readonly maxLineBytes?: number;
};

export type DiagnosticWriter = (message: string) => void;

export function createDiagnosticWriter(stream: Writable): DiagnosticWriter {
  let blocked = false;
  return (message): void => {
    if (blocked || stream.destroyed) return;
    if (stream.write(`${message}\n`)) return;
    blocked = true;
    const ready = (): void => {
      stream.off("drain", ready);
      stream.off("close", ready);
      stream.off("error", ready);
      blocked = false;
    };
    stream.once("drain", ready);
    stream.once("close", ready);
    stream.once("error", ready);
  };
}

export function spawnTransport(
  options: TransportOptions,
): {
  child: ChildProcessWithoutNullStreams;
  serverRequests: ServerRequestTracker;
  diagnostic: DiagnosticWriter;
} {
  const diagnostic = createDiagnosticWriter(options.clientErr);
  const child = spawn(options.command, options.args, {
    stdio: ["pipe", "pipe", "pipe"],
    env: childEnv(options.env),
  });
  const serverRequests = createServerRequestTracker({
    maxLineBytes: options.maxLineBytes,
    onAmbiguous: () => {
      diagnostic("vinctor-mcp-pep: dropped ambiguous server line (fail-closed)");
    },
    onOversize: () => {
      diagnostic("vinctor-mcp-pep: dropped oversized server line (fail-closed)");
    },
    onUntrackable: () => {
      diagnostic("vinctor-mcp-pep: dropped untrackable server request (fail-closed)");
    },
  });
  child.stdout.pipe(serverRequests.observer).pipe(options.clientOut, { end: false });
  child.stderr.pipe(options.clientErr, { end: false });
  child.stdin.on("error", () => {});
  return { child, serverRequests, diagnostic };
}

function assertWritable(stream: Writable): void {
  if (stream.destroyed || !stream.writable) {
    throw new Error("cannot write to a closed stream");
  }
}

export async function writeLine(stream: Writable, raw: Buffer): Promise<void> {
  assertWritable(stream);
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    let completedWrites = 0;
    const cleanup = (): void => {
      stream.off("close", closed);
      stream.off("error", failed);
    };
    const succeed = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve();
    };
    const failed = (error: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const closed = (): void => {
      failed(new Error("stream closed before the line was written"));
    };
    const written = (error?: Error | null): void => {
      if (error) {
        failed(error);
        return;
      }
      completedWrites += 1;
      if (completedWrites === 2) succeed();
    };
    stream.once("close", closed);
    stream.once("error", failed);
    try {
      stream.write(raw, written);
      stream.write("\n", written);
    } catch (error) {
      failed(error instanceof Error ? error : new Error("stream write failed"));
    }
    if (stream.destroyed || !stream.writable) {
      closed();
    }
  });
}

export async function writeBufferedLine(stream: Writable, raw: Buffer): Promise<void> {
  assertWritable(stream);
  const accepted = stream.write(raw);
  const newlineAccepted = stream.write("\n");
  if (stream.destroyed || !stream.writable) {
    throw new Error("stream closed before the line was written");
  }
  if (accepted && newlineAccepted) return;

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = (): void => {
      stream.off("drain", succeed);
      stream.off("close", closed);
      stream.off("error", failed);
    };
    const succeed = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve();
    };
    const failed = (error: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const closed = (): void => {
      failed(new Error("stream closed before the line was written"));
    };
    stream.once("drain", succeed);
    stream.once("close", closed);
    stream.once("error", failed);
    if (stream.destroyed || !stream.writable) {
      closed();
    }
  });
}

export async function pumpLines(
  input: Readable,
  splitter: LineSplitter,
  handleLine: (raw: Buffer) => Promise<void>,
): Promise<void> {
  for await (const chunk of input) {
    const buf = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
    for (const line of splitter.push(buf)) {
      try {
        await handleLine(line);
      } catch {}
    }
  }

  const rest = splitter.flush();
  if (rest !== null) {
    try {
      await handleLine(rest);
    } catch {}
  }
}
