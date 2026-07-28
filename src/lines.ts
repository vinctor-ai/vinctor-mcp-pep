/**
 * Byte-level newline splitter for MCP stdio framing (one JSON-RPC message per
 * `\n`-terminated line). Works on Buffers so that a multi-byte UTF-8 character
 * split across chunks is never corrupted, and so pass-through can re-emit the
 * ORIGINAL bytes (byte-faithful proxying — no re-serialization).
 */
export const DEFAULT_MAX_LINE_BYTES = 8 * 1024 * 1024;

type LineSplitterOptions = {
  readonly maxLineBytes?: number;
  readonly onOversize?: () => void;
};

export class LineSplitter {
  private buffer: Buffer | null = null;
  private bufferedBytes = 0;
  private droppingOversize = false;
  private readonly maxLineBytes: number;
  private readonly onOversize?: () => void;

  constructor(options: LineSplitterOptions = {}) {
    const maxLineBytes = options.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES;
    if (!Number.isSafeInteger(maxLineBytes) || maxLineBytes < 1) {
      throw new RangeError("maxLineBytes must be a positive safe integer");
    }
    this.maxLineBytes = maxLineBytes;
    this.onOversize = options.onOversize;
  }

  /** Feed a chunk; returns the complete lines it terminated (without `\n`). */
  push(chunk: Buffer): Buffer[] {
    const lines: Buffer[] = [];
    let offset = 0;
    while (offset < chunk.length) {
      const newline = chunk.indexOf(0x0a, offset);
      if (this.droppingOversize) {
        if (newline < 0) return lines;
        this.droppingOversize = false;
        offset = newline + 1;
        continue;
      }

      const end = newline < 0 ? chunk.length : newline;
      const segment = chunk.subarray(offset, end);
      if (this.bufferedBytes + segment.length > this.maxLineBytes) {
        this.buffer = null;
        this.bufferedBytes = 0;
        this.droppingOversize = true;
        this.onOversize?.();
        if (newline < 0) return lines;
        this.droppingOversize = false;
        offset = newline + 1;
        continue;
      }

      if (newline < 0) {
        this.append(segment);
        return lines;
      }
      if (this.bufferedBytes === 0) {
        lines.push(segment.length === 0 ? Buffer.alloc(0) : segment);
      } else {
        this.append(segment);
        lines.push(this.takeBufferedLine());
      }
      offset = newline + 1;
    }
    return lines;
  }

  /** Any trailing bytes not yet terminated by `\n` (null if none). */
  flush(): Buffer | null {
    if (this.droppingOversize) {
      this.droppingOversize = false;
      return null;
    }
    if (this.bufferedBytes === 0) return null;
    return this.takeBufferedLine();
  }

  private append(segment: Buffer): void {
    if (segment.length === 0) return;
    const requiredBytes = this.bufferedBytes + segment.length;
    if (requiredBytes > this.maxLineBytes) {
      throw new RangeError("line exceeds maxLineBytes");
    }
    if (this.buffer === null || this.buffer.length < requiredBytes) {
      let capacity =
        this.buffer === null
          ? Math.min(this.maxLineBytes, Math.max(4096, requiredBytes))
          : this.buffer.length;
      while (capacity < requiredBytes) {
        capacity = Math.min(this.maxLineBytes, capacity * 2);
      }
      const grown = Buffer.allocUnsafe(capacity);
      if (this.buffer !== null) {
        this.buffer.copy(grown, 0, 0, this.bufferedBytes);
      }
      this.buffer = grown;
    }
    segment.copy(this.buffer, this.bufferedBytes);
    this.bufferedBytes = requiredBytes;
  }

  private takeBufferedLine(): Buffer {
    const source = this.buffer!;
    const exactBacking =
      source.byteOffset === 0 &&
      source.byteLength === this.bufferedBytes &&
      source.buffer.byteLength === this.bufferedBytes;
    const line = exactBacking ? source : Buffer.allocUnsafeSlow(this.bufferedBytes);
    if (!exactBacking) {
      source.copy(line, 0, 0, this.bufferedBytes);
    }
    this.buffer = null;
    this.bufferedBytes = 0;
    return line;
  }
}
