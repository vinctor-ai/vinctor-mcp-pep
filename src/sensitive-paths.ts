/**
 * Sensitive-path overlay: paths that denote credential material classify
 * over `secret/<kind>` instead of `fs/<path>`, so a broad fs grant can never
 * quietly cover reading, writing, or deleting `.env` files, ssh keys, or
 * cloud-credential files.
 *
 * Vendored from vinctor-claude-code-hook src/classifiers/sensitive-paths.ts
 * (vinctor-hermes-plugin resources.py is the Python sibling): the same
 * pattern table, kinds, and first-match-wins order. The hooks match with
 * micromatch(patterns, { dot: true }); this proxy is stdlib-only
 * (AGENTS.md), so the four fixed pattern groups are ported as exact segment
 * predicates instead of a glob engine:
 *
 *   secret/ssh   ** /.ssh/id_*   ** /.ssh/*.pem   ** /*.pem
 *   secret/aws   ** /.aws/credentials
 *   secret/gcp   ** /.config/gcloud/** /credentials*
 *   secret/env   .env   ** /.env   .env.*   ** /.env.*
 *
 * (spaces inside the globs above only keep this comment token-safe)
 *
 * Predicate ↔ glob equivalence, over normalizeFsPath outputs: a leading
 * `**\/` matches zero or more segments, so the root-anchored `.env` /
 * `.env.*` spellings are subsumed and every group reduces to a predicate on
 * the last one or two segments (plus, for gcp, an adjacent
 * `.config/gcloud` pair strictly before the last segment — the middle `**`
 * also matches zero segments). `*` matches the empty string and any
 * non-`/` characters; with dot:true a leading dot is permitted, which the
 * startsWith/endsWith checks reproduce. Verified case-by-case against the
 * hooks' micromatch behavior.
 *
 * PKA-100 / PKA-133 divergence from the hooks: matching is CASE-FOLDED,
 * SEPARATOR-FOLDED, and TRAILING-DOT/SPACE-FOLDED to host-FS semantics,
 * where micromatch (and the hooks) match the literal string. Host
 * filesystems resolve more spellings to the same file than a case-sensitive
 * glob does:
 *
 *   - the default macOS and Windows filesystems are case-insensitive —
 *     open("/w/.ENV") resolves the real .env;
 *   - Windows treats `\` as a path separator;
 *   - Win32 CreateFile strips trailing `.` and ` ` from each path component
 *     — CreateFile(".env ") opens .env (PKA-133).
 *
 * A spelling that escapes the overlay maps to plain fs/<path> and slides
 * under a broad fs grant: the exact secret-disclosure this overlay exists
 * to prevent. PKA-133 was the third instance of that one bug — PKA-100
 * folded case and separators here but left the trailing dot/space, which
 * defeated the exact-equality (`.env`, `.aws/credentials`) and endsWith
 * (`*.pem`) predicates while the startsWith ones survived by luck.
 *
 * The proxy cannot know which host, volume, or API the wrapped server will
 * resolve a path on (even Linux mounts case-insensitive volumes), so it
 * folds UNCONDITIONALLY — no host detection, no platform branch. This is
 * sound because each fold is an OVER-APPROXIMATION: it only ever classifies
 * MORE spellings as secrets, never fewer, so it is fail-closed on EVERY
 * host. Worst case, a genuinely distinct `.ENV` or `.env ` file on a
 * case-sensitive Unix volume needs a secret/env grant instead of an fs one.
 * That is the same argument PKA-100's case fold used.
 *
 * The fold governs MATCHING ONLY. It never rewrites the emitted resource:
 * a non-sensitive path still maps to `fs/<path>` verbatim (mapper.ts), so
 * `notes.txt ` stays `fs/notes.txt ` and only the secret verdict is widened.
 *
 * What string folding cannot catch (symlinks, hardlinks, Unicode-lookalike
 * names, 8.3 short names) needs realpath resolution against the live FS —
 * out of scope here and tracked as follow-up.
 *
 * Canon: the fold is pinned by vinctor-conformance
 * fixtures/sensitive-paths.json, vendored at test/fixtures/ with a recorded
 * sha256, so this adapter and the hooks cannot drift apart on it.
 *
 * Input contract: a normalizeFsPath-normalized path (non-empty segments,
 * no `.`/`..`), though any `/`-joined path is tolerated. The hooks
 * pre-expand `~/` to the home directory; here a literal leading `~`
 * segment needs no expansion — every effective pattern is `**\/`-prefixed,
 * so one extra leading segment cannot change the verdict.
 */

type SensitiveKind = {
  readonly resource: string;
  readonly matches: (segments: readonly string[], last: string) => boolean;
};

const SENSITIVE_KINDS: readonly SensitiveKind[] = [
  {
    // **/.ssh/id_*  |  **/.ssh/*.pem (subsumed by **/*.pem)  |  **/*.pem
    resource: "secret/ssh",
    matches: (segments, last) =>
      (segments.length >= 2 && segments[segments.length - 2] === ".ssh" && last.startsWith("id_")) ||
      last.endsWith(".pem"),
  },
  {
    // **/.aws/credentials
    resource: "secret/aws",
    matches: (segments, last) =>
      segments.length >= 2 && segments[segments.length - 2] === ".aws" && last === "credentials",
  },
  {
    // **/.config/gcloud/**/credentials*
    resource: "secret/gcp",
    matches: (segments, last) => {
      if (!last.startsWith("credentials")) return false;
      for (let i = 0; i + 2 < segments.length; i++) {
        if (segments[i] === ".config" && segments[i + 1] === "gcloud") return true;
      }
      return false;
    },
  },
  {
    // .env | **/.env | .env.* | **/.env.*
    resource: "secret/env",
    matches: (_segments, last) => last === ".env" || last.startsWith(".env."),
  },
];

/** `secret/<kind>` if the normalized path denotes credential material, else null. */
export function classifySensitivePath(normalizedPath: string): string | null {
  // Fold to host-FS semantics (see header). Splitting on `\` as well treats
  // Windows separators as separators; the pattern table is all-lowercase, so
  // lowercasing each segment makes the match case-insensitive; stripping
  // trailing `.` and ` ` from each segment matches what Win32 CreateFile
  // strips per path component (PKA-133) — without it a single trailing space
  // defeats every exact-equality and endsWith predicate below.
  const segments = normalizedPath
    .split(/[/\\]+/)
    .filter((s) => s.length > 0)
    .map((s) => s.toLowerCase().replace(/[. ]+$/, ""));
  const last = segments[segments.length - 1];
  if (last === undefined) return null;
  for (const kind of SENSITIVE_KINDS) {
    if (kind.matches(segments, last)) return kind.resource;
  }
  return null;
}
