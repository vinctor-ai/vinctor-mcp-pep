import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { popCanonical, popMac, buildProof } from "../src/pop.js";

/**
 * GOLDEN cross-check against the REAL Python implementation
 * (vinctor-core src/vinctor_service/pop.py). Generated with:
 *
 *   .venv/bin/python -c 'from vinctor_service.pop import pop_canonical, pop_mac
 *   c = pop_canonical("read","fs/a",1752000000,"nonce-abc","vtk_test")
 *   print(c.hex()); print(pop_mac("s3cret-xyz", c))
 *   c2 = pop_canonical("write","fs/π/파일.txt",1700000001,"n.o.n.c.e","vtk_x")
 *   print(pop_mac("秘密-sekret", c2))'
 *
 * If these ever fail, the TS proof would be REJECTED by the server's
 * verify_pop — never "fix" the golden, fix the framing/mac code.
 */
const GOLDEN_CANONICAL_HEX =
  "00000004726561640000000466732f610000000a31373532303030303030" +
  "000000096e6f6e63652d6162630000000876746b5f74657374";
const GOLDEN_MAC = "1jVA9tDe8KnGuLEO64yGMgtC8MDeC9uhoXmsG30dC6w";
const GOLDEN_MAC_UNICODE = "5XK_2rpZOewwis0Lv7QpBjscKkQ0D8ZrulvuTwhCHPs";

describe("popCanonical — length-prefixed framing (byte-exact vs Python)", () => {
  it("matches the Python pop_canonical bytes for the golden input", () => {
    const c = popCanonical("read", "fs/a", 1752000000, "nonce-abc", "vtk_test");
    assert.equal(c.toString("hex"), GOLDEN_CANONICAL_HEX);
  });

  it("each field is 4-byte big-endian UTF-8 length + bytes, in order", () => {
    const c = popCanonical("a", "bc", 7, "n", "t");
    // [1]"a" [2]"bc" [1]"7" [1]"n" [1]"t"
    assert.equal(
      c.toString("hex"),
      "0000000161" + "000000026263" + "0000000137" + "000000016e" + "0000000174",
    );
  });

  it("length prefixes lock field boundaries: (ab,c) !== (a,bc)", () => {
    const one = popCanonical("ab", "c", 1, "n", "t");
    const two = popCanonical("a", "bc", 1, "n", "t");
    assert.notEqual(one.toString("hex"), two.toString("hex"));
  });

  it("lengths count UTF-8 BYTES, not code units (multi-byte content)", () => {
    const c = popCanonical("π", "", 0, "", "");
    // "π" is 2 UTF-8 bytes (cf80); the empty fields are 4 zero bytes each.
    assert.equal(
      c.toString("hex"),
      "00000002cf80" + "00000000" + "0000000130" + "00000000" + "00000000",
    );
  });
});

describe("popMac — HMAC-SHA256, base64url unpadded (byte-exact vs Python)", () => {
  it("matches the Python pop_mac for the golden input", () => {
    const mac = popMac(
      "s3cret-xyz",
      popCanonical("read", "fs/a", 1752000000, "nonce-abc", "vtk_test"),
    );
    assert.equal(mac, GOLDEN_MAC);
  });

  it("matches the Python pop_mac for a unicode secret and fields", () => {
    const mac = popMac(
      "秘密-sekret",
      popCanonical("write", "fs/π/파일.txt", 1700000001, "n.o.n.c.e", "vtk_x"),
    );
    assert.equal(mac, GOLDEN_MAC_UNICODE);
  });

  it("is deterministic and unpadded base64url", () => {
    const c = popCanonical("read", "fs/a", 1, "n", "t");
    const a = popMac("k", c);
    assert.equal(a, popMac("k", c));
    assert.match(a, /^[A-Za-z0-9_-]+$/); // no '=', '+', '/'
    assert.equal(a.length, 43); // 32-byte digest, unpadded
  });
});

describe("buildProof — <ts>.<nonce>.<mac>", () => {
  it("is three dot-joined parts whose mac binds ts/nonce/action/resource/token_id", () => {
    const proof = buildProof("sec", "vtk_1", "read", "fs/a", 1752000000);
    const parts = proof.split(".");
    assert.equal(parts.length, 3);
    const [ts, nonce, mac] = parts as [string, string, string];
    assert.equal(ts, "1752000000");
    assert.ok(nonce.length > 0);
    assert.match(nonce, /^[A-Za-z0-9_-]+$/); // base64url: can never contain "."
    assert.equal(mac, popMac("sec", popCanonical("read", "fs/a", 1752000000, nonce, "vtk_1")));
  });

  it("generates a fresh unique nonce per call", () => {
    const nonces = new Set<string>();
    for (let i = 0; i < 50; i++) {
      nonces.add(buildProof("sec", "vtk_1", "read", "fs/a", 1).split(".")[1]!);
    }
    assert.equal(nonces.size, 50);
  });

  it("defaults ts to current unix seconds", () => {
    const before = Math.floor(Date.now() / 1000);
    const ts = Number(buildProof("sec", "vtk_1", "read", "fs/a").split(".")[0]);
    const after = Math.floor(Date.now() / 1000);
    assert.ok(Number.isInteger(ts));
    assert.ok(ts >= before && ts <= after);
  });
});
