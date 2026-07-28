import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { PassThrough, Writable } from "node:stream";
import { writeLine } from "../src/stdio.js";

class BlockedWritable extends Writable {
  constructor() {
    super({ highWaterMark: 1 });
  }

  override _write(
    _chunk: Buffer,
    _encoding: BufferEncoding,
    _callback: (error?: Error | null) => void,
  ): void {}
}

class AsyncErrorWritable extends Writable {
  override _write(
    _chunk: Buffer,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    setImmediate(() => callback(new Error("async pipe failure")));
  }
}

describe("writeLine", () => {
  it("writes the original bytes followed by exactly one newline", async () => {
    const stream = new PassThrough();
    const chunks: Buffer[] = [];
    stream.on("data", (chunk: Buffer) => chunks.push(chunk));

    await writeLine(stream, Buffer.from('{"jsonrpc":"2.0"}', "utf8"));

    assert.equal(Buffer.concat(chunks).toString("utf8"), '{"jsonrpc":"2.0"}\n');
  });

  it("rejects a stream that was already destroyed", async () => {
    const stream = new PassThrough();
    stream.destroy();

    await assert.rejects(writeLine(stream, Buffer.from("message")), /closed stream/);
  });

  it("rejects close or error while waiting for backpressure to drain", async () => {
    const closed = new BlockedWritable();
    const closeResult = writeLine(closed, Buffer.from("message"));
    closed.destroy();
    await assert.rejects(closeResult, /closed before/);

    const errored = new BlockedWritable();
    const errorResult = writeLine(errored, Buffer.from("message"));
    errored.destroy(new Error("write failed"));
    await assert.rejects(errorResult, /write failed/);
  });

  it("rejects an asynchronous write callback error after the writes were accepted", async () => {
    const stream = new AsyncErrorWritable();
    stream.on("error", () => {});

    await assert.rejects(writeLine(stream, Buffer.from("message")), /async pipe failure/);
  });
});
