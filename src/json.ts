const WHITESPACE = new Set([" ", "\t", "\n", "\r"]);
const MAX_NESTING_DEPTH = 512;
const STRICT_UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

class ObjectKeyScanner {
  private index = 0;

  constructor(private readonly text: string) {}

  scan(): boolean {
    this.skipWhitespace();
    const duplicate = this.scanValue(0);
    this.skipWhitespace();
    if (this.index !== this.text.length) throw new SyntaxError("trailing JSON data");
    return duplicate;
  }

  private scanValue(depth: number): boolean {
    if (depth > MAX_NESTING_DEPTH) throw new RangeError("JSON nesting is too deep");
    const char = this.text[this.index];
    if (char === "{") return this.scanObject(depth + 1);
    if (char === "[") return this.scanArray(depth + 1);
    if (char === '"') {
      this.scanString(false);
      return false;
    }
    this.scanPrimitive();
    return false;
  }

  private scanObject(depth: number): boolean {
    this.index += 1;
    this.skipWhitespace();
    if (this.consume("}")) return false;
    const keys = new Set<string>();
    while (true) {
      const key = this.scanString(true);
      if (keys.has(key)) return true;
      keys.add(key);
      this.skipWhitespace();
      this.expect(":");
      this.skipWhitespace();
      if (this.scanValue(depth)) return true;
      this.skipWhitespace();
      if (this.consume("}")) return false;
      this.expect(",");
      this.skipWhitespace();
    }
  }

  private scanArray(depth: number): boolean {
    this.index += 1;
    this.skipWhitespace();
    if (this.consume("]")) return false;
    while (true) {
      if (this.scanValue(depth)) return true;
      this.skipWhitespace();
      if (this.consume("]")) return false;
      this.expect(",");
      this.skipWhitespace();
    }
  }

  private scanString(decode: boolean): string {
    const start = this.index;
    this.expect('"');
    while (this.index < this.text.length) {
      const char = this.text[this.index];
      this.index += 1;
      if (char === '"') {
        return decode ? (JSON.parse(this.text.slice(start, this.index)) as string) : "";
      }
      if (char === "\\") {
        this.index += 1;
      }
    }
    throw new SyntaxError("unterminated JSON string");
  }

  private scanPrimitive(): void {
    while (this.index < this.text.length) {
      const char = this.text[this.index]!;
      if (char === "," || char === "]" || char === "}" || WHITESPACE.has(char)) return;
      this.index += 1;
    }
  }

  private skipWhitespace(): void {
    while (this.index < this.text.length && WHITESPACE.has(this.text[this.index]!)) {
      this.index += 1;
    }
  }

  private consume(expected: string): boolean {
    if (this.text[this.index] !== expected) return false;
    this.index += 1;
    return true;
  }

  private expect(expected: string): void {
    if (!this.consume(expected)) throw new SyntaxError(`expected ${expected}`);
  }
}

export function hasDuplicateObjectKeys(text: string): boolean {
  try {
    return new ObjectKeyScanner(text).scan();
  } catch {
    return true;
  }
}

export function decodeUtf8Strict(bytes: Uint8Array): string | null {
  try {
    return STRICT_UTF8_DECODER.decode(bytes);
  } catch {
    return null;
  }
}
