import { createHmac, randomBytes } from "node:crypto";

/**
 * HMAC proof-of-possession (PoP) proof generation for subject tokens.
 *
 * Byte-exact client counterpart of vinctor-core `src/vinctor_service/pop.py`
 * (ADR 0007 C3): the server's `verify_pop` recomputes this mac, so any framing
 * drift is a hard deny. Cross-checked against the real Python output by golden
 * vectors in test/pop.test.ts — change nothing here without re-deriving them.
 */

/**
 * Length-prefixed canonical bytes for the proof binding: each field is a
 * 4-byte big-endian length of its UTF-8 bytes followed by those bytes, in the
 * fixed order [action, resource, String(ts), nonce, token_id]. Length-prefixed
 * (NOT delimiter-joined) so no field content can shift the parse.
 */
export function popCanonical(
  action: string,
  resource: string,
  ts: number,
  nonce: string,
  tokenId: string,
): Buffer {
  const parts = [action, resource, String(ts), nonce, tokenId];
  const chunks: Buffer[] = [];
  for (const p of parts) {
    const bytes = Buffer.from(p, "utf8");
    const len = Buffer.alloc(4);
    len.writeUInt32BE(bytes.length, 0);
    chunks.push(len, bytes);
  }
  return Buffer.concat(chunks);
}

/** base64url (UNPADDED) of HMAC-SHA256(pop_secret, canonical) — Python's
 * `urlsafe_b64encode(...).rstrip(b"=")`. */
export function popMac(popSecret: string, canonical: Buffer): string {
  return createHmac("sha256", Buffer.from(popSecret, "utf8"))
    .update(canonical)
    .digest()
    .toString("base64url");
}

/**
 * Build the `X-Subject-Token-Proof` header value `<ts>.<nonce>.<mac>` for one
 * enforce call: current unix seconds, a fresh random nonce (base64url — never
 * contains "."), and the mac binding (action, resource, ts, nonce, token_id).
 */
export function buildProof(
  popSecret: string,
  tokenId: string,
  action: string,
  resource: string,
  nowUnixSeconds: number = Math.floor(Date.now() / 1000),
): string {
  const nonce = randomBytes(16).toString("base64url");
  const mac = popMac(popSecret, popCanonical(action, resource, nowUnixSeconds, nonce, tokenId));
  return `${nowUnixSeconds}.${nonce}.${mac}`;
}
