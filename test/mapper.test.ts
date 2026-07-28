import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { mapToolCall } from "../src/mapper.js";

describe("mapToolCall — filesystem tools", () => {
  const cases: Array<[tool: string, action: string]> = [
    ["read_text_file", "read"],
    ["read_file", "read"],
    ["read_media_file", "read"],
    ["list_directory", "read"],
    ["list_directory_with_sizes", "read"],
    ["directory_tree", "read"],
    ["search_files", "read"],
    ["get_file_info", "read"],
    ["write_file", "write"],
    ["edit_file", "write"],
    ["create_directory", "write"],
    ["delete_directory", "delete"],
    ["remove_directory", "delete"],
  ];
  for (const [tool, action] of cases) {
    it(`${tool} → ${action} fs/<path>`, () => {
      assert.deepEqual(mapToolCall(tool, { path: "/home/u/notes.txt" }), {
        action,
        resource: "fs/home/u/notes.txt",
      });
    });
  }

  it("delete_file → delete fs/<path> under the filesystem server prefix", () => {
    const expected = { action: "delete", resource: "fs/home/u/notes.txt" };
    assert.deepEqual(mapToolCall("filesystem__delete_file", { path: "/home/u/notes.txt" }), expected);
    assert.deepEqual(mapToolCall("mcp__filesystem__delete_file", { path: "/home/u/notes.txt" }), expected);
  });

  it("move_file → write over the destination, AND read+delete over the source (PKA-100)", () => {
    // Enforcing the destination alone let a file be moved OUT of a protected
    // subtree under a grant covering only the destination. A move is three
    // effects: source disclosed at a new location (read), source removed
    // (delete), destination gains state (write) — ALL must be permitted.
    assert.deepEqual(mapToolCall("move_file", { source: "/a/draft.txt", destination: "/b/final.txt" }), {
      action: "write",
      resource: "fs/b/final.txt",
      alsoRequires: [
        { action: "read", resource: "fs/a/draft.txt" },
        { action: "delete", resource: "fs/a/draft.txt" },
      ],
    });
  });

  it("move_file requires BOTH endpoints resolvable (never move an ambiguous target)", () => {
    assert.equal(mapToolCall("move_file", { destination: "/b/final.txt" }), null);
    assert.equal(mapToolCall("move_file", { source: "/a" }), null);
    assert.equal(mapToolCall("move_file", { source: "/a/../x", destination: "/b" }), null);
    assert.equal(mapToolCall("move_file", { source: "/a", destination: "/b/../x" }), null);
    assert.equal(mapToolCall("move_file", { source: 1, destination: "/b" }), null);
  });

  it("read_multiple_files with only non-sensitive paths maps one read per path (PKA-148)", () => {
    // The old canon v1 boundary left these unmapped (deny fail-closed but
    // unauthorizable); with set-valued requirements they are N ordinary reads.
    assert.deepEqual(mapToolCall("read_multiple_files", { paths: ["/a", "/b"] }), {
      action: "read",
      resource: "fs/a",
      alsoRequires: [{ action: "read", resource: "fs/b" }],
    });
    assert.deepEqual(mapToolCall("read_multiple_files", { paths: ["/a"] }), {
      action: "read",
      resource: "fs/a",
    });
    assert.equal(mapToolCall("read_multiple_files", {}), null);
    assert.equal(mapToolCall("read_multiple_files", { paths: [] }), null);
  });

  it("list_allowed_directories → read fs/_allowed-dirs (no path argument)", () => {
    assert.deepEqual(mapToolCall("list_allowed_directories", {}), {
      action: "read",
      resource: "fs/_allowed-dirs",
    });
  });

  it("accepts server-prefixed and mcp__-prefixed names", () => {
    const expected = { action: "read", resource: "fs/etc/hosts" };
    assert.deepEqual(mapToolCall("filesystem__read_text_file", { path: "/etc/hosts" }), expected);
    assert.deepEqual(mapToolCall("mcp__filesystem__read_text_file", { path: "/etc/hosts" }), expected);
  });

  it("normalizes duplicate slashes and trailing slash", () => {
    assert.deepEqual(mapToolCall("list_directory", { path: "//var//log/" }), {
      action: "read",
      resource: "fs/var/log",
    });
  });

  it("folds Windows separators so one file is one resource", () => {
    // The sensitive overlay already folds separators; the fs/ fallback must
    // too, or `fs/C:\Users\a\notes.txt` and `fs/C:/Users/a/notes.txt` are two
    // audit identities for one Windows file and a prefix scope only matches
    // the spelling the caller happened to send.
    const expected = { action: "read", resource: "fs/C:/Users/a/notes.txt" };
    assert.deepEqual(mapToolCall("read_text_file", { path: "C:\\Users\\a\\notes.txt" }), expected);
    assert.deepEqual(mapToolCall("read_text_file", { path: "C:/Users/a/notes.txt" }), expected);
    assert.deepEqual(mapToolCall("read_text_file", { path: "C:/Users\\a/notes.txt" }), expected);
  });

  it("rejects traversal segments (resources are path-prefixes; .. escapes scopes)", () => {
    assert.equal(mapToolCall("read_text_file", { path: "/safe/../etc/shadow" }), null);
    assert.equal(mapToolCall("write_file", { path: ".." }), null);
    assert.equal(mapToolCall("write_file", { path: "./x" }), null);
    assert.equal(
      mapToolCall("read_text_file", {
        path: "C:/Users/alice/..\\..\\Windows/system32/config/SAM",
      }),
      null,
    );
  });

  it("rejects missing / non-string / empty / NUL paths", () => {
    assert.equal(mapToolCall("read_text_file", {}), null);
    assert.equal(mapToolCall("read_text_file", { path: 42 }), null);
    assert.equal(mapToolCall("read_text_file", { path: "" }), null);
    assert.equal(mapToolCall("read_text_file", { path: "/a\0b" }), null);
    assert.equal(mapToolCall("read_text_file", { path: "///" }), null);
  });

  it("rejects a filesystem tool under a contradicting server prefix", () => {
    assert.equal(mapToolCall("github__read_text_file", { path: "/etc/hosts" }), null);
  });
});

describe("mapToolCall — filesystem sensitive-path overlay (secret/<kind>)", () => {
  it("write_file .env → write:secret/env (not fs/<path>)", () => {
    assert.deepEqual(mapToolCall("write_file", { path: ".env", content: "x" }), {
      action: "write",
      resource: "secret/env",
    });
    assert.deepEqual(mapToolCall("mcp__filesystem__write_file", { path: "/home/u/proj/.env" }), {
      action: "write",
      resource: "secret/env",
    });
  });

  it("sensitive reads → read:secret/<kind>, preserving the action", () => {
    assert.deepEqual(mapToolCall("read_text_file", { path: "/home/u/.env" }), {
      action: "read",
      resource: "secret/env",
    });
    assert.deepEqual(mapToolCall("read_text_file", { path: "/home/u/.ssh/id_rsa" }), {
      action: "read",
      resource: "secret/ssh",
    });
    assert.deepEqual(mapToolCall("read_text_file", { path: "/home/u/cert.pem" }), {
      action: "read",
      resource: "secret/ssh",
    });
    assert.deepEqual(mapToolCall("get_file_info", { path: "/home/u/.aws/credentials" }), {
      action: "read",
      resource: "secret/aws",
    });
    assert.deepEqual(mapToolCall("read_text_file", { path: "/home/u/.config/gcloud/credentials.db" }), {
      action: "read",
      resource: "secret/gcp",
    });
  });

  it("sensitive deletes → delete:secret/<kind>", () => {
    assert.deepEqual(mapToolCall("filesystem__delete_file", { path: "/home/u/.ssh/id_rsa" }), {
      action: "delete",
      resource: "secret/ssh",
    });
    assert.deepEqual(mapToolCall("filesystem__delete_file", { path: "/home/u/.aws/credentials" }), {
      action: "delete",
      resource: "secret/aws",
    });
  });

  it("a leading ~ segment needs no expansion (every pattern is **/-prefixed)", () => {
    assert.deepEqual(mapToolCall("read_text_file", { path: "~/.ssh/id_ed25519" }), {
      action: "read",
      resource: "secret/ssh",
    });
    assert.deepEqual(mapToolCall("read_text_file", { path: "~/.aws/credentials" }), {
      action: "read",
      resource: "secret/aws",
    });
  });

  it("normal paths still map to fs/<path> (overlay is a strict overlay)", () => {
    assert.deepEqual(mapToolCall("write_file", { path: "/home/u/notes.txt" }), {
      action: "write",
      resource: "fs/home/u/notes.txt",
    });
    // Near-misses the hooks also leave as fs/<path>: the kinds are files,
    // not directories, and the segment predicates are exact.
    for (const path of ["/home/u/.ssh", "/home/u/.envrc", "/home/u/.environment", "/x/.ssh/nested/id_rsa", "/x/.aws/credentials/extra"]) {
      const got = mapToolCall("read_text_file", { path });
      assert.ok(got !== null && got.resource.startsWith("fs/"), `${path} → ${got?.resource}`);
    }
  });

  it("overlay matches case-folded and separator-folded, like the host FS (PKA-100)", () => {
    // On a case-insensitive FS (macOS/Windows default), open("/w/.ENV")
    // resolves the real .env — every case/separator spelling must classify
    // as the secret, or an fs/** grant covers the credential bytes.
    assert.deepEqual(mapToolCall("read_text_file", { path: "/workspace/.ENV" }), {
      action: "read",
      resource: "secret/env",
    });
    assert.deepEqual(mapToolCall("read_text_file", { path: "/home/u/.SSH/ID_RSA" }), {
      action: "read",
      resource: "secret/ssh",
    });
    assert.deepEqual(mapToolCall("write_file", { path: "/w/.Env.local", content: "x" }), {
      action: "write",
      resource: "secret/env",
    });
    assert.deepEqual(mapToolCall("read_text_file", { path: "C:\\Users\\u\\.ENV" }), {
      action: "read",
      resource: "secret/env",
    });
  });

  it("PDP dot-segment rejection still precedes the overlay (stricter than the hooks)", () => {
    assert.equal(mapToolCall("read_text_file", { path: "/safe/../.env" }), null);
    assert.equal(mapToolCall("write_file", { path: "./.env" }), null);
  });

  it("move_file: sensitive source wins the primary pair; both endpoints fully enforced", () => {
    // Primary pair stays canon/hook-compatible (sensitive source, then
    // sensitive destination, else destination); alsoRequires adds the
    // remaining per-endpoint checks (PKA-100).
    assert.deepEqual(mapToolCall("move_file", { source: "/home/u/.env", destination: "/tmp/x" }), {
      action: "write",
      resource: "secret/env",
      alsoRequires: [
        { action: "read", resource: "secret/env" },
        { action: "delete", resource: "secret/env" },
        { action: "write", resource: "fs/tmp/x" },
      ],
    });
    assert.deepEqual(mapToolCall("move_file", { source: "/tmp/x", destination: "/home/u/.aws/credentials" }), {
      action: "write",
      resource: "secret/aws",
      alsoRequires: [
        { action: "read", resource: "fs/tmp/x" },
        { action: "delete", resource: "fs/tmp/x" },
      ],
    });
    assert.deepEqual(mapToolCall("move_file", { source: "/home/u/.env", destination: "/home/u/.aws/credentials" }), {
      action: "write",
      resource: "secret/env",
      alsoRequires: [
        { action: "read", resource: "secret/env" },
        { action: "delete", resource: "secret/env" },
        { action: "write", resource: "secret/aws" },
      ],
    });
    // Both endpoints must still normalize — traversal unmaps even when the
    // other endpoint is sensitive.
    assert.equal(mapToolCall("move_file", { source: "/home/u/.env", destination: "/b/../x" }), null);
    assert.equal(mapToolCall("move_file", { source: "/a/../x", destination: "/home/u/.env" }), null);
  });

  it("read_multiple_files: every member is required, the first secret keeps the primary (PKA-148)", () => {
    // The old shape returned the first credential-shaped path ALONE, so a
    // secret/env grant read the other members unenforced. The primary stays
    // that same pair; the rest of the list rides in alsoRequires.
    assert.deepEqual(mapToolCall("read_multiple_files", { paths: ["/p/a.ts", "/home/u/.env", "/p/b.ts"] }), {
      action: "read",
      resource: "secret/env",
      alsoRequires: [
        { action: "read", resource: "fs/p/a.ts" },
        { action: "read", resource: "fs/p/b.ts" },
      ],
    });
    // Two credential kinds are two requirements; the first in scan order is
    // the primary.
    assert.deepEqual(mapToolCall("read_multiple_files", { paths: ["/home/u/.ssh/id_rsa", "/home/u/.env"] }), {
      action: "read",
      resource: "secret/ssh",
      alsoRequires: [{ action: "read", resource: "secret/env" }],
    });
    // Paths folding to the same resource are one requirement.
    assert.deepEqual(mapToolCall("read_multiple_files", { paths: ["/home/u/.env", "/home/u2/.env"] }), {
      action: "read",
      resource: "secret/env",
    });
    // A member that fails to normalize unmaps the WHOLE call wherever it
    // sits: charging the expressible subset would authorize a call that
    // still reads the inexpressible path.
    assert.equal(mapToolCall("read_multiple_files", { paths: ["/p/../x", "/home/u/.env"] }), null);
    assert.equal(mapToolCall("read_multiple_files", { paths: ["/p/a.ts", "//", "/home/u/.env"] }), null);
    assert.equal(mapToolCall("read_multiple_files", { paths: ["/home/u/.env", 42] }), null);
  });
});

describe("mapToolCall — github tools", () => {
  const ar = { owner: "acme", repo: "api" };

  // (tool, extra args, action, kind) over github/acme/api/<kind>
  const repoCases: Array<[string, Record<string, unknown>, string, string]> = [
    // issues
    ["get_issue", { issue_number: 7 }, "read", "issue"],
    ["issue_read", { issue_number: 7 }, "read", "issue"],
    ["list_issues", {}, "read", "issue"],
    ["create_issue", { title: "t" }, "write", "issue"],
    ["update_issue", { issue_number: 7 }, "write", "issue"],
    ["issue_write", { issue_number: 7 }, "write", "issue"],
    ["add_issue_comment", { issue_number: 7, body: "b" }, "write", "issue"],
    ["add_sub_issue", { issue_number: 7 }, "write", "issue"],
    // pull requests
    ["get_pull_request", { pull_number: 42 }, "read", "pr"],
    ["pull_request_read", { pull_number: 42 }, "read", "pr"],
    ["list_pull_requests", {}, "read", "pr"],
    ["create_pull_request", { head: "f", base: "main" }, "write", "pr"],
    ["update_pull_request", { pull_number: 42 }, "write", "pr"],
    ["create_pull_request_review", { pull_number: 42, event: "APPROVE" }, "write", "pr"],
    ["pull_request_review_write", { pull_number: 42 }, "write", "pr"],
    ["merge_pull_request", { pull_number: 42 }, "deploy", "pr"],
    // contents (canon collapses file/code/branch kinds into `contents`)
    ["get_file_contents", { path: "src/i.js" }, "read", "contents"],
    ["get_repository_tree", {}, "read", "contents"],
    ["list_commits", {}, "read", "contents"],
    ["get_commit", { sha: "abc" }, "read", "contents"],
    ["list_branches", {}, "read", "contents"],
    ["list_tags", {}, "read", "contents"],
    ["get_tag", { tag: "v1" }, "read", "contents"],
    ["create_or_update_file", { path: "src/i.js", branch: "f" }, "write", "contents"],
    ["push_files", { branch: "f" }, "write", "contents"],
    ["create_branch", { branch: "f" }, "write", "contents"],
    // releases — publishing is externally effective → deploy (canon)
    ["list_releases", {}, "read", "release"],
    ["get_latest_release", {}, "read", "release"],
    ["get_release_by_tag", { tag: "v1" }, "read", "release"],
    ["get_release", { tag: "v1" }, "read", "release"],
    ["create_release", { tag: "v1" }, "deploy", "release"],
    ["publish_release", { tag: "v1" }, "deploy", "release"],
    // workflows: run/rerun execute arbitrary CI, cancel is a bounded write,
    // deleting logs is destructive
    ["actions_list", {}, "read", "workflow"],
    ["actions_get", {}, "read", "workflow"],
    ["get_job_logs", { job_id: 3 }, "read", "workflow"],
    ["list_workflows", {}, "read", "workflow"],
    ["list_workflow_runs", {}, "read", "workflow"],
    ["get_workflow_run", { run_id: 314 }, "read", "workflow"],
    ["download_workflow_run_artifact", { artifact_id: 9 }, "read", "workflow"],
    ["run_workflow", { workflow_id: "ci.yml" }, "execute", "workflow"],
    ["rerun_workflow_run", { run_id: 314 }, "execute", "workflow"],
    ["rerun_failed_jobs", { run_id: 314 }, "execute", "workflow"],
    ["cancel_workflow_run", { run_id: 314 }, "write", "workflow"],
    ["delete_workflow_run_logs", { run_id: 314 }, "delete", "workflow"],
    // code security / dependabot (beyond-canon kind, hook parity)
    ["get_code_scanning_alert", { alert_number: 1 }, "read", "security"],
    ["list_code_scanning_alerts", {}, "read", "security"],
    ["get_dependabot_alert", { alert_number: 1 }, "read", "security"],
    ["list_dependabot_alerts", {}, "read", "security"],
    // secret scanning — canon kind `secret` under the repo scope
    ["get_secret_scanning_alert", { alert_number: 5 }, "read", "secret"],
    ["list_secret_scanning_alerts", {}, "read", "secret"],
    // misc repo-scoped
    ["list_repository_collaborators", {}, "read", "collaborator"],
    // fork_repository is multi-effect (PKA-149) — tested separately below.
  ];
  for (const [tool, extra, action, kind] of repoCases) {
    it(`${tool} → ${action} github/<owner>/<repo>/${kind}`, () => {
      assert.deepEqual(mapToolCall(tool, { ...ar, ...extra }), {
        action,
        resource: `github/acme/api/${kind}`,
      });
    });
  }

  it("github delete_file → delete github/<owner>/<repo>/contents under the github prefix", () => {
    const args = { ...ar, path: "src/i.js", branch: "f" };
    const expected = { action: "delete", resource: "github/acme/api/contents" };
    assert.deepEqual(mapToolCall("github__delete_file", args), expected);
    assert.deepEqual(mapToolCall("mcp__github__delete_file", args), expected);
  });

  it("bare delete_file is ambiguous (filesystem fork AND classic github) → unmapped", () => {
    // Args are caller-controlled; guessing the family from arg shape could
    // enforce against the wrong resource tree. Only prefixed forms map.
    assert.equal(mapToolCall("delete_file", { path: "/home/u/notes.txt" }), null);
    assert.equal(mapToolCall("delete_file", { ...ar, path: "src/i.js" }), null);
  });

  it("actions_run_trigger dispatches on method; unknown/missing method → unmapped", () => {
    const run = { ...ar, method: "run_workflow", workflow_id: "ci.yml" };
    assert.deepEqual(mapToolCall("actions_run_trigger", run), {
      action: "execute",
      resource: "github/acme/api/workflow",
    });
    assert.deepEqual(mapToolCall("actions_run_trigger", { ...ar, method: "cancel_workflow_run" }), {
      action: "write",
      resource: "github/acme/api/workflow",
    });
    assert.deepEqual(mapToolCall("actions_run_trigger", { ...ar, method: "delete_workflow_run_logs" }), {
      action: "delete",
      resource: "github/acme/api/workflow",
    });
    assert.equal(mapToolCall("actions_run_trigger", { ...ar }), null);
    assert.equal(mapToolCall("actions_run_trigger", { ...ar, method: "detonate" }), null);
  });

  it("global-scoped tools bind github/_/<kind>", () => {
    assert.deepEqual(mapToolCall("get_me", {}), { action: "read", resource: "github/_/context" });
    assert.deepEqual(mapToolCall("search_repositories", { query: "q" }), {
      action: "read",
      resource: "github/_/repo",
    });
    assert.deepEqual(mapToolCall("search_code", { query: "q" }), {
      action: "read",
      resource: "github/_/contents",
    });
    // create_repository is NO LONGER global (PKA-150) — see the namespace tests.
  });

  it("create_repository is a namespace write github/<org>/_/repo (PKA-150)", () => {
    // Owner from `organization`; the old namespace-less github/_/repo could not
    // tell "create in myorg" from "create anywhere".
    assert.deepEqual(mapToolCall("create_repository", { organization: "myorg", name: "n" }), {
      action: "write",
      resource: "github/myorg/_/repo",
    });
    // No organization → the coarse, unscoped namespace, never nothing.
    assert.deepEqual(mapToolCall("create_repository", { name: "n" }), {
      action: "write",
      resource: "github/_/_/repo",
    });
    // A malformed organization is never guessed around (mcp-pep is stricter).
    assert.equal(mapToolCall("create_repository", { organization: "a/b", name: "n" }), null);
  });

  it("fork_repository charges source fork + source read + destination namespace write (PKA-149)", () => {
    assert.deepEqual(mapToolCall("fork_repository", { owner: "acme", repo: "api", organization: "myorg" }), {
      action: "write",
      resource: "github/acme/api/fork",
      alsoRequires: [
        { action: "read", resource: "github/acme/api/contents" },
        { action: "write", resource: "github/myorg/_/repo" },
      ],
    });
    // No destination org → the unscoped github/_/_/repo, still charged.
    assert.deepEqual(mapToolCall("fork_repository", { owner: "acme", repo: "api" }), {
      action: "write",
      resource: "github/acme/api/fork",
      alsoRequires: [
        { action: "read", resource: "github/acme/api/contents" },
        { action: "write", resource: "github/_/_/repo" },
      ],
    });
    // An ambiguous source never forks; a malformed destination unmaps.
    assert.equal(mapToolCall("fork_repository", { owner: "acme", organization: "myorg" }), null);
    assert.equal(mapToolCall("fork_repository", { owner: "acme", repo: "api", organization: "a/b" }), null);
  });

  it("owner-scoped tools bind github/<owner>/_/<kind>; reads degrade without owner", () => {
    assert.deepEqual(mapToolCall("get_team_members", { owner: "acme", team_slug: "t" }), {
      action: "read",
      resource: "github/acme/_/context",
    });
    assert.deepEqual(mapToolCall("get_team_members", { team_slug: "t" }), {
      action: "read",
      resource: "github/_/context",
    });
    assert.deepEqual(mapToolCall("list_issue_types", { owner: "acme" }), {
      action: "read",
      resource: "github/acme/_/issue",
    });
  });

  it("flex-scoped searches narrow to whatever target is present", () => {
    assert.deepEqual(mapToolCall("search_issues", { query: "q", ...ar }), {
      action: "read",
      resource: "github/acme/api/issue",
    });
    assert.deepEqual(mapToolCall("search_issues", { query: "q", owner: "acme" }), {
      action: "read",
      resource: "github/acme/_/issue",
    });
    assert.deepEqual(mapToolCall("search_issues", { query: "q" }), {
      action: "read",
      resource: "github/_/issue",
    });
    assert.deepEqual(mapToolCall("search_pull_requests", { query: "q" }), {
      action: "read",
      resource: "github/_/pr",
    });
  });

  it("repo-scoped reads degrade to `_` segments when owner/repo are absent", () => {
    assert.deepEqual(mapToolCall("get_issue", { issue_number: 7 }), {
      action: "read",
      resource: "github/_/issue",
    });
    assert.deepEqual(mapToolCall("list_pull_requests", { owner: "acme" }), {
      action: "read",
      resource: "github/acme/_/pr",
    });
  });

  it("repo-scoped mutations require owner AND repo (never mutate an ambiguous target)", () => {
    assert.equal(mapToolCall("create_issue", { title: "t" }), null);
    assert.equal(mapToolCall("create_issue", { owner: "acme" }), null);
    assert.equal(mapToolCall("merge_pull_request", { pull_number: 42 }), null);
    assert.equal(mapToolCall("run_workflow", { workflow_id: "ci.yml" }), null);
    assert.equal(mapToolCall("mcp__github__delete_file", { path: "x" }), null);
  });

  it("present-but-malformed owner/repo never maps — not even for reads (PDP defense)", () => {
    assert.equal(mapToolCall("create_issue", { owner: "a/b", repo: "r" }), null);
    assert.equal(mapToolCall("create_issue", { owner: "..", repo: "r" }), null);
    assert.equal(mapToolCall("create_issue", { owner: "", repo: "r" }), null);
    assert.equal(mapToolCall("create_issue", { owner: "acme", repo: 7 }), null);
    assert.equal(mapToolCall("get_issue", { owner: "..", repo: "api", issue_number: 7 }), null);
    assert.equal(mapToolCall("get_issue", { owner: "acme", repo: "a/b" }), null);
    assert.equal(mapToolCall("get_me", { owner: ".." }), null);
    assert.equal(mapToolCall("search_issues", { owner: "a\0b" }), null);
  });
});

describe("mapToolCall — slack tools", () => {
  const ch = { channel_id: "C0123ABCD" };

  const workspaceReads = [
    // reference @modelcontextprotocol/server-slack (slack_*) + Zencoder fork
    "slack_list_channels",
    "slack_get_users",
    "slack_get_user_profile",
    // korotovsky slack-mcp-server
    "channels_list",
    "channels_me",
    "conversations_unreads",
    "users_search",
  ];
  for (const tool of workspaceReads) {
    it(`${tool} → read chat/slack (workspace-scoped)`, () => {
      assert.deepEqual(mapToolCall(tool, {}), { action: "read", resource: "chat/slack" });
    });
  }

  const channelReads = [
    "slack_get_channel_history",
    "slack_get_thread_replies",
    "conversations_history",
    "conversations_replies",
  ];
  for (const tool of channelReads) {
    it(`${tool} → read chat/slack/<channel>`, () => {
      assert.deepEqual(mapToolCall(tool, { ...ch }), {
        action: "read",
        resource: "chat/slack/C0123ABCD",
      });
    });
  }

  const channelSends = [
    "slack_post_message",
    "slack_reply_to_thread",
    "slack_add_reaction",
    "conversations_add_message",
    "conversations_join",
    "conversations_leave",
    "conversations_mark",
    "reactions_add",
    "reactions_remove",
  ];
  for (const tool of channelSends) {
    it(`${tool} → send chat/slack/<channel>`, () => {
      assert.deepEqual(mapToolCall(tool, { ...ch, text: "hi" }), {
        action: "send",
        resource: "chat/slack/C0123ABCD",
      });
    });
  }

  it("channel reads degrade to chat/slack when channel_id is absent", () => {
    assert.deepEqual(mapToolCall("conversations_history", {}), {
      action: "read",
      resource: "chat/slack",
    });
  });

  it("sends never target an ambiguous channel (absent channel_id → unmapped)", () => {
    assert.equal(mapToolCall("slack_post_message", { text: "hi" }), null);
    assert.equal(mapToolCall("conversations_add_message", { payload: "hi" }), null);
  });

  it("conversations_search_messages → read chat/slack, narrowed by filter_in_channel", () => {
    assert.deepEqual(mapToolCall("conversations_search_messages", { search_query: "q" }), {
      action: "read",
      resource: "chat/slack",
    });
    assert.deepEqual(
      mapToolCall("conversations_search_messages", { search_query: "q", filter_in_channel: "C042ENGOPS" }),
      { action: "read", resource: "chat/slack/C042ENGOPS" },
    );
  });

  it("present-but-malformed channel segments never map (PDP defense)", () => {
    assert.equal(mapToolCall("slack_post_message", { channel_id: "C1/..", text: "hi" }), null);
    assert.equal(mapToolCall("slack_post_message", { channel_id: "..", text: "hi" }), null);
    assert.equal(mapToolCall("slack_post_message", { channel_id: "", text: "hi" }), null);
    assert.equal(mapToolCall("conversations_history", { channel_id: 7 }), null);
    assert.equal(mapToolCall("conversations_history", { channel_id: "a\0b" }), null);
    assert.equal(mapToolCall("conversations_search_messages", { filter_in_channel: "a/b" }), null);
  });

  it("accepts server-prefixed and mcp__-prefixed names; contradictions do not map", () => {
    assert.deepEqual(mapToolCall("mcp__slack__slack_post_message", { ...ch, text: "hi" }), {
      action: "send",
      resource: "chat/slack/C0123ABCD",
    });
    assert.deepEqual(mapToolCall("slack__conversations_history", { ...ch }), {
      action: "read",
      resource: "chat/slack/C0123ABCD",
    });
    assert.equal(mapToolCall("github__slack_post_message", { ...ch, text: "hi" }), null);
    assert.equal(mapToolCall("slack__get_issue", { owner: "acme", repo: "api" }), null);
  });
});

describe("mapToolCall — unmapped ⇒ null (proxy denies fail-closed)", () => {
  it("does not resolve inherited Object.prototype names as table entries", () => {
    assert.equal(
      mapToolCall("filesystem__toString", { path: "/root/.ssh/id_rsa" }),
      null,
    );
    assert.equal(mapToolCall("github__toString", { owner: "o", repo: "r" }), null);
    assert.equal(mapToolCall("slack__valueOf", {}), null);
    assert.equal(mapToolCall("filesystem____proto__", { path: "/x" }), null);
  });

  it("unknown tools do not map", () => {
    assert.equal(mapToolCall("execute_shell", { command: "rm -rf /" }), null);
    assert.equal(mapToolCall("mcp__slack__post_message", { channel: "#x" }), null);
    assert.equal(mapToolCall("upload_file", { path: "/a" }), null);
  });

  it("malformed names do not map", () => {
    assert.equal(mapToolCall("", { path: "/x" }), null);
    assert.equal(mapToolCall("__read_text_file", { path: "/x" }), null);
    assert.equal(mapToolCall("filesystem__", { path: "/x" }), null);
    assert.equal(mapToolCall("read\0_text_file", { path: "/x" }), null);
  });
});
