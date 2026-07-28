import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { classifySensitivePath } from "../src/sensitive-paths.js";
import { fsPathResource } from "../src/mapper.js";

// Vendored from vinctor-claude-code-hook src/classifiers/sensitive-paths.ts —
// same kinds, same verdicts, with one deliberate divergence: matching is
// folded to host-FS semantics — case (PKA-100), separators (PKA-100), and the
// trailing dot/space Win32 CreateFile strips (PKA-133) — where the hooks match
// the literal string like micromatch. Inputs here are normalizeFsPath outputs
// (relative, non-empty segments), which is what the mapper feeds it.
//
// The canonical vector set for the fold lives in vinctor-conformance and is
// exercised by sensitive-paths-canon.test.ts; this suite keeps the local
// predicate-by-predicate coverage. Every credential-shaped path below is a
// DECOY string — nothing here opens a file.

describe("classifySensitivePath", () => {
  it("maps .env variants to secret/env (same cases as the hooks' suite)", () => {
    for (const p of [".env", "project/.env", ".env.production", "a/b/.env.local", "~/.env"]) {
      assert.equal(classifySensitivePath(p), "secret/env", p);
    }
  });

  it("maps ssh keys and pem files to secret/ssh (same cases as the hooks' suite)", () => {
    for (const p of ["home/u/.ssh/id_rsa", ".ssh/id_ed25519", "certs/server.pem", "~/.ssh/id_rsa", ".ssh/key.pem"]) {
      assert.equal(classifySensitivePath(p), "secret/ssh", p);
    }
  });

  it("maps aws credentials to secret/aws", () => {
    assert.equal(classifySensitivePath("home/u/.aws/credentials"), "secret/aws");
    assert.equal(classifySensitivePath(".aws/credentials"), "secret/aws");
  });

  it("maps gcloud credentials to secret/gcp (middle ** matches zero or more dirs)", () => {
    assert.equal(classifySensitivePath(".config/gcloud/x/credentials.db"), "secret/gcp");
    assert.equal(classifySensitivePath("home/u/.config/gcloud/credentials"), "secret/gcp");
  });

  it("returns null for non-sensitive paths", () => {
    for (const p of ["src/app.ts", "README.md", "package.json", "home/u/notes.txt"]) {
      assert.equal(classifySensitivePath(p), null, p);
    }
  });

  it("returns null for near-misses, exactly like micromatch would", () => {
    const nearMisses = [
      ".envrc", // not .env / .env.*
      ".environment",
      "env",
      "x/env.local", // no leading dot
      ".ssh", // the directory itself, not a key under it
      "x/.ssh/nested/id_rsa", // .ssh must be the immediate parent for id_*
      "x/.ssh/id_rsa/more", // id_* must be the final segment
      ".aws/credentials/extra", // credentials must be the final segment
      "x/.aws/creds",
      ".config/gcloud/legacy_credentials", // final segment must START with credentials
      "gcloud/.config/credentials", // .config/gcloud must be adjacent, in order
      ".config/gcloud", // needs a credentials* segment after gcloud
      "cert.pem.bak", // *.pem must be the suffix of the final segment
    ];
    for (const p of nearMisses) {
      assert.equal(classifySensitivePath(p), null, p);
    }
  });

  it("matches case-folded, like the host FS (PKA-100: .ENV resolves the real .env)", () => {
    // Default macOS/Windows filesystems are case-insensitive: open("/w/.ENV")
    // resolves the real .env. The overlay must classify every case spelling
    // as the secret, or a broad fs grant quietly covers credential material.
    assert.equal(classifySensitivePath(".ENV"), "secret/env");
    assert.equal(classifySensitivePath("workspace/.Env"), "secret/env");
    assert.equal(classifySensitivePath("w/.ENV.LOCAL"), "secret/env");
    assert.equal(classifySensitivePath("X/.SSH/ID_RSA"), "secret/ssh");
    assert.equal(classifySensitivePath("home/u/.SSH/id_ed25519"), "secret/ssh");
    assert.equal(classifySensitivePath("certs/SERVER.PEM"), "secret/ssh");
    assert.equal(classifySensitivePath("home/u/.AWS/Credentials"), "secret/aws");
    assert.equal(classifySensitivePath(".Config/GCloud/x/CREDENTIALS.db"), "secret/gcp");
  });

  it("case-folded near-misses still return null (no new false positives)", () => {
    for (const p of [".ENVRC", "ENV", "X/.SSH/nested/ID_RSA", "CERT.PEM.BAK", "x/.AWS/creds"]) {
      assert.equal(classifySensitivePath(p), null, p);
    }
  });

  it("treats backslashes as separators, like the host FS on Windows (PKA-100)", () => {
    assert.equal(classifySensitivePath("workspace\\.env"), "secret/env");
    assert.equal(classifySensitivePath("C:\\Users\\u\\.ssh\\id_rsa"), "secret/ssh");
    assert.equal(classifySensitivePath("home/u\\.aws\\credentials"), "secret/aws");
    assert.equal(classifySensitivePath("C:\\Users\\u\\.ENV"), "secret/env");
  });

  it("strips the trailing dot/space Win32 CreateFile strips (PKA-133)", () => {
    // CreateFile(".env ") opens .env: Win32 drops trailing '.' and ' ' from
    // each path component. PKA-100 folded case and separators but not this, so
    // a single trailing space defeated every exact-equality and endsWith
    // predicate — .env, .aws/credentials and *.pem all fell through to
    // fs/<path> and under a broad fs/** grant. The startsWith predicates
    // (id_*, credentials*, .env.*) happened to survive; they are pinned below
    // so they stay caught deliberately rather than by luck.
    //
    // Every row here is the probe table from the PKA-133 report.
    assert.equal(classifySensitivePath(".env "), "secret/env");
    assert.equal(classifySensitivePath(".ENV "), "secret/env");
    assert.equal(classifySensitivePath("h/.aws/credentials "), "secret/aws");
    assert.equal(classifySensitivePath("h/.aws/credentials."), "secret/aws");
    assert.equal(classifySensitivePath("k.pem "), "secret/ssh");
    assert.equal(classifySensitivePath("k.pem."), "secret/ssh");
    assert.equal(classifySensitivePath(".env."), "secret/env");
    assert.equal(classifySensitivePath("h/.ssh/id_rsa "), "secret/ssh");
  });

  it("folds trailing dot/space per SEGMENT, not just the last one (PKA-133)", () => {
    // Win32 strips them from every path component, so a trailing space on a
    // parent directory resolves the same file too.
    assert.equal(classifySensitivePath("h/.ssh /id_rsa"), "secret/ssh");
    assert.equal(classifySensitivePath("h/.aws./credentials"), "secret/aws");
    assert.equal(classifySensitivePath(".config/gcloud /x/credentials"), "secret/gcp");
    assert.equal(classifySensitivePath(".env  "), "secret/env"); // a run, not one char
    assert.equal(classifySensitivePath(".env. "), "secret/env"); // dot and space mixed
  });

  it("the reported escape classifies as the secret (PKA-133 end to end)", () => {
    // Operator grants read:fs/** and withholds secret/**; the agent asks for
    // 'C:\\workspace\\.env '. Before the fold this mapped to fs/c:/workspace/.env ,
    // was permitted under fs/**, and CreateFile opened the real .env.
    assert.equal(classifySensitivePath("C:\\workspace\\.env "), "secret/env");
    assert.equal(fsPathResource("C:\\workspace\\.env "), "secret/env");
  });

  it("the trailing-dot/space fold is a STRIP, not a blanket (no new false positives)", () => {
    // Stripping must not widen the overlay to ordinary files: each of these
    // strips to a string that is still a near-miss.
    for (const p of [
      "notes.txt ",
      "cert.pem.bak ", // -> cert.pem.bak, still not a *.pem
      ".envrc ", // -> .envrc, still not .env
      ".environment.", // -> .environment
      "env ", // -> env, still no leading dot
      "x/.aws/creds ", // -> creds, still not credentials
      "x/.ssh/nested/id_rsa ", // .ssh still not the immediate parent
      ".config/gcloud/legacy_credentials ", // still does not START with credentials
    ]) {
      assert.equal(classifySensitivePath(p), null, p);
    }
  });

  it("the fold never rewrites the emitted resource — only the verdict widens", () => {
    // A non-sensitive path keeps its spelling verbatim in fs/<path>; the fold
    // exists for MATCHING only. (Separator normalisation here is mapper.ts's
    // pre-existing normalizeFsPath, not the overlay's fold.)
    assert.equal(fsPathResource("notes.txt "), "fs/notes.txt ");
    assert.equal(fsPathResource("cert.pem.bak "), "fs/cert.pem.bak ");
    assert.equal(fsPathResource("README.md"), "fs/README.md"); // case not folded either
  });

  it("star-matches-empty edges behave like micromatch", () => {
    assert.equal(classifySensitivePath(".ssh/id_"), "secret/ssh"); // id_* with empty *
    assert.equal(classifySensitivePath("certs/.pem"), "secret/ssh"); // *.pem with empty * (dot:true)
    assert.equal(classifySensitivePath(".env."), "secret/env"); // .env.* with empty *
    assert.equal(classifySensitivePath(".config/gcloud/credentials"), "secret/gcp"); // credentials* with empty *
  });

  it("first matching kind wins, in the hooks' table order (ssh, aws, gcp, env)", () => {
    // *.pem (ssh group) beats the gcp group for a .pem file under gcloud.
    assert.equal(classifySensitivePath(".config/gcloud/credentials.pem"), "secret/ssh");
  });
});
