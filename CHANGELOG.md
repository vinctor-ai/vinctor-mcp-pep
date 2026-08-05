# Changelog

Notable changes to `vinctor-mcp-pep`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file was adopted at `0.4.0`. Earlier releases are listed by version and
date only and are not reconstructed change-by-change; their notes live in the
release PRs.

## [0.4.0] - 2026-08-06

**Upgrade if you run with `unmapped_verdict: "allow"`.** On `0.3.0` a single
`/./` in a path was enough to turn a gated `secret/ssh` read into an unaudited
pass-through. The mapper refused every path containing a traversal segment, a
refusal the proxy reported as "I do not know this tool" — which is exactly what
`unmapped_verdict: "allow"` is documented to forward.

```
/decoy/.ssh/id_rsa            ->  read:secret/ssh          (gated)
/decoy/./.ssh/id_rsa          ->  unmapped -> FORWARDED    (not gated)
/decoy/work/../.ssh/id_rsa    ->  unmapped -> FORWARDED    (not gated)
```

Both spellings now map to `read:secret/ssh`, so there is nothing left for the
escape hatch to forward. That is the fix — not making the refusal louder.

This release requires no config change, and it does not ask you to abandon
`unmapped_verdict`. Read "What breaks": it changes what the proxy forwards.

### ⚠️ What breaks

- **An argument the mapper cannot express is now a hard deny that
  `unmapped_verdict` does not reach.** `..`, `/a/../..`, `../../etc/passwd` and
  anything else escaping above its root return `PARSE_UNSAFE` rather than
  `null`. `null` means "I do not know this tool" and the proxy honours the
  operator's documented escape hatch for it; `PARSE_UNSAFE` means "I know this
  tool and this argument cannot be named", which is a refusal no configuration
  overrides. The refusal is still observed, so it is auditable rather than
  silent.

  If you were relying on `unmapped_verdict: "allow"` to pass traversal
  arguments through, those calls now fail.
- **Calls that used to be forwarded unauthorized are now authorized — and may be
  denied.** Any path with a `.` or an in-bounds `..` segment previously went out
  as unmapped. It now maps to a real `(action, resource)` pair and is charged
  against your grants. A grant that does not cover the folded resource will deny
  a call that previously went through. This is the point of the release, but it
  is a behaviour change on live traffic, so check your grants against the folded
  spellings first.
- **Resource strings for paths are folded, so some of them changed.** `/a/b` and
  `/a/x/../b` are one file and were two resources. An operator rule or an audit
  query written against an unfolded spelling will no longer match.

### Changed

- **Ordinary relative paths are no longer refused.** `./a/b` maps to
  `read:fs/a/b` and `/a/b/../c` to `read:fs/a/c`. Refusing every traversal
  segment was correct for `../../etc/passwd` and wrong for `./a/b`, an ordinary
  relative path — and refusing ordinary work is what pushed operators onto the
  `unmapped_verdict` escape hatch in the first place. The over-strictness was
  not free; it manufactured the bypass.
- **Folding happens before the sensitive-path overlay**, so traversal cannot
  dodge secret classification: `/safe/../.env` classifies as `secret/env`.
- Escape above the root is decided on the **folded** result, so `/a/../..` is
  caught even though it carries no leading `..`.

### Known limits

- Escape detection is textual and root-relative. The mapper does not resolve
  symlinks and does not consult the filesystem, so a path that stays textually
  in-bounds and escapes through a link is not caught here.
