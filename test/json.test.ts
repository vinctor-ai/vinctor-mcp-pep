import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { decodeUtf8Strict, hasDuplicateObjectKeys } from "../src/json.js";

describe("hasDuplicateObjectKeys", () => {
  it("accepts unique keys, including the same name in sibling objects", () => {
    assert.equal(hasDuplicateObjectKeys('{"left":{"id":1},"right":{"id":2}}'), false);
  });

  it("detects duplicate keys at every nesting level", () => {
    assert.equal(hasDuplicateObjectKeys('{"method":"tools/call","method":"ping"}'), true);
    assert.equal(hasDuplicateObjectKeys('{"params":{"name":"a","name":"b"}}'), true);
  });

  it("compares decoded key names rather than raw escape spellings", () => {
    assert.equal(hasDuplicateObjectKeys('{"method":"ping","m\\u0065thod":"tools/call"}'), true);
  });
});

describe("decodeUtf8Strict", () => {
  it("preserves a leading BOM so JSON parsing rejects bytes the proxy would forward", () => {
    const bytes = Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from('{"jsonrpc":"2.0","id":1,"method":"ping"}'),
    ]);
    const decoded = decodeUtf8Strict(bytes);

    assert.ok(decoded?.startsWith("\uFEFF"));
    assert.throws(() => JSON.parse(decoded!));
  });
});
