import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { LineSplitter } from "../src/lines.js";

const s = (b: Buffer): string => b.toString("utf8");

describe("LineSplitter", () => {
  it("splits complete lines and buffers the remainder", () => {
    const sp = new LineSplitter();
    const lines = sp.push(Buffer.from('{"a":1}\n{"b":2}\npartial'));
    assert.deepEqual(lines.map(s), ['{"a":1}', '{"b":2}']);
    assert.deepEqual(sp.push(Buffer.from("-done\n")).map(s), ["partial-done"]);
    assert.equal(sp.flush(), null);
  });

  it("reassembles a multi-byte UTF-8 character split across chunks", () => {
    const sp = new LineSplitter();
    const bytes = Buffer.from('{"p":"héllo"}\n'); // é = 2 bytes
    const cut = bytes.indexOf(Buffer.from("é")) + 1; // mid-character
    assert.deepEqual(sp.push(bytes.subarray(0, cut)), []);
    const lines = sp.push(bytes.subarray(cut));
    assert.deepEqual(lines.map(s), ['{"p":"héllo"}']);
  });

  it("preserves bytes exactly (no trimming, \\r kept)", () => {
    const sp = new LineSplitter();
    const lines = sp.push(Buffer.from('  {"a": 1}  \r\n'));
    assert.deepEqual(lines.map(s), ['  {"a": 1}  \r']);
  });

  it("flush returns unterminated trailing bytes once", () => {
    const sp = new LineSplitter();
    sp.push(Buffer.from("tail"));
    assert.equal(s(sp.flush()!), "tail");
    assert.equal(sp.flush(), null);
  });

  it("drops an oversized line while draining through its newline, then recovers", () => {
    let oversized = 0;
    const sp = new LineSplitter({
      maxLineBytes: 4,
      onOversize: () => {
        oversized += 1;
      },
    });
    assert.deepEqual(sp.push(Buffer.from("abcde")), []);
    assert.deepEqual(sp.push(Buffer.from("f\nokay\n")).map(s), ["okay"]);
    assert.equal(oversized, 1);
    assert.equal(sp.flush(), null);
  });

  it("accepts a line exactly at the configured bound", () => {
    const sp = new LineSplitter({ maxLineBytes: 4 });
    assert.deepEqual(sp.push(Buffer.from("four\n")).map(s), ["four"]);
  });

  it("guards the internal append invariant above the configured bound", () => {
    const sp = new LineSplitter({ maxLineBytes: 4 }) as unknown as {
      append(segment: Buffer): void;
    };
    assert.throws(() => sp.append(Buffer.from("five!")), /exceeds maxLineBytes/);
  });

  it("concatenates a highly fragmented line only once at its newline", () => {
    const originalConcat = Buffer.concat;
    let concatCalls = 0;
    Buffer.concat = (list, totalLength) => {
      concatCalls += 1;
      return originalConcat(list, totalLength);
    };
    try {
      const sp = new LineSplitter({ maxLineBytes: 128 });
      for (let index = 0; index < 128; index += 1) {
        assert.deepEqual(sp.push(Buffer.from("x")), []);
      }
      assert.deepEqual(sp.push(Buffer.from("\n")).map(s), ["x".repeat(128)]);
      assert.ok(concatCalls <= 1);
    } finally {
      Buffer.concat = originalConcat;
    }
  });

  it("does not retain one Buffer object per fragment", () => {
    const sp = new LineSplitter({ maxLineBytes: 10_000 });
    const byte = Buffer.from("x");
    for (let index = 0; index < 10_000; index += 1) {
      assert.deepEqual(sp.push(byte), []);
    }

    const state = sp as unknown as Record<string, unknown>;
    const retainedBuffers = Object.values(state).reduce<number>(
      (count, value) =>
        count +
        (Buffer.isBuffer(value)
          ? 1
          : Array.isArray(value)
            ? value.filter(Buffer.isBuffer).length
            : 0),
      0,
    );
    assert.ok(retainedBuffers <= 32);
    assert.equal(s(sp.flush()!), "x".repeat(10_000));
  });

  it("does not retain the growth buffer behind an emitted short line", () => {
    const sp = new LineSplitter();
    assert.deepEqual(sp.push(Buffer.from("x")), []);
    const [line] = sp.push(Buffer.from("\n"));

    assert.equal(line!.length, 1);
    assert.equal(line!.buffer.byteLength, 1);
  });
});
