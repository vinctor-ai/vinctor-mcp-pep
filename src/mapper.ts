/**
 * Pure mapper: MCP tool call → Vinctor (action, resource).
 *
 * Covers the MCP-tool canon families (vinctor-conformance, fixtures v1):
 * filesystem, github, slack — mirroring the sibling adapters
 * (vinctor-claude-code-hook src/classifiers/mcp/*, vinctor-hermes-plugin
 * mcp.py) so the same tool call means the same thing on every runtime.
 * Anything it does not map returns null, which the proxy treats as a
 * fail-closed deny WITHOUT calling the enforce service (AGENTS.md: unmapped
 * tools default to fail-closed deny; policy-configurable later).
 *
 * Accepted tool-name forms: `read_text_file`, `filesystem__read_text_file`,
 * `mcp__filesystem__read_text_file`. A server prefix that contradicts the
 * table entry's server (e.g. `github__read_text_file`) does NOT map. A BARE
 * name claimed by more than one family (e.g. `delete_file`, which is both a
 * filesystem-fork tool and a classic GitHub tool) does NOT map either: args
 * are caller-controlled, so guessing the family from arg shape could enforce
 * against the wrong resource tree. The prefixed forms are unambiguous.
 *
 * Deliberately stricter than the hooks in one respect: a present-but-
 * malformed target segment (owner/repo/channel containing `/`, `.`/`..`,
 * NUL, or non-string) unmaps the whole call — the hooks may degrade reads to
 * the `_` unknown-segment convention there. Absent segments degrade exactly
 * like the hooks; malformed ones are never guessed around (PDP
 * defense-in-depth: resources are hierarchical path-prefixes, and `.`/`..`
 * segments are traversal).
 *
 * Filesystem paths that denote credential material (`.env`, ssh keys,
 * cloud-credential files) classify over `secret/<kind>` instead of
 * `fs/<path>` — the same sensitive-path overlay the hooks apply (see
 * sensitive-paths.ts), so a broad fs grant never quietly covers secrets.
 */

import { classifySensitivePath } from "./sensitive-paths.js";

export type Action = "read" | "write" | "execute" | "deploy" | "delete" | "send";

/**
 * PKA-159: a tool this mapper RECOGNISES whose argument it cannot express.
 *
 * Distinct from `null` (tool not in any family table) on purpose. `null` means
 * "I do not know this tool", and the proxy honours the operator's documented
 * `unmapped_verdict: "allow"` escape hatch for it. This does NOT: the tool is
 * known and the ARGUMENT is inexpressible, so forwarding it would run a call
 * whose target was never named to the PDP. Before this split, adding one `/./`
 * to a path turned a gated `secret/ssh` read into an unaudited pass-through.
 *
 * Same distinction the hooks carry as `ParseUnsafe` vs `Unmapped` (PKA-148).
 */
export const PARSE_UNSAFE = Object.freeze({ parseUnsafe: true as const });

export type MapResult = MappedCall | typeof PARSE_UNSAFE | null;

export function isParseUnsafe(r: MapResult): r is typeof PARSE_UNSAFE {
  return r !== null && "parseUnsafe" in r;
}

export type MappedCall = {
  readonly action: Action;
  readonly resource: string;
  /**
   * Additional (action, resource) permits that must ALSO hold before the
   * call may forward (PKA-100: move_file requires read+delete on the source
   * and write on the destination). The primary pair above stays the
   * canon/hook-compatible mapping; the proxy enforces the primary pair AND
   * every entry here, denying unless all permit.
   */
  readonly alsoRequires?: readonly { readonly action: Action; readonly resource: string }[];
};

function ownEntry<T>(table: Readonly<Record<string, T>>, key: string): T | undefined {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

function parseToolName(name: string): { server: string | null; tool: string } | null {
  if (name.length === 0 || name.includes("\0")) return null;
  let rest = name;
  if (rest.startsWith("mcp__")) rest = rest.slice("mcp__".length);
  const sep = rest.indexOf("__");
  if (sep === 0) return null; // "__tool" — malformed
  if (sep > 0) {
    const tool = rest.slice(sep + 2);
    if (tool.length === 0) return null;
    return { server: rest.slice(0, sep), tool };
  }
  return { server: null, tool: rest };
}

/**
 * Normalize a filesystem path into resource segments. Vinctor resources are
 * hierarchical path-prefixes, so `.`/`..` segments are traversal and must be
 * rejected outright (PDP defense-in-depth: never emit a resource a wildcard
 * scope could be escaped through).
 *
 * `\` is folded to `/` for the same reason the sensitive-path overlay folds
 * it (sensitive-paths.ts header, PKA-100): on Windows it IS a separator, so
 * keeping the caller's spelling would emit two resource identifiers —
 * `fs/C:\Users\a\notes.txt` and `fs/C:/Users/a/notes.txt` — for one file,
 * splitting its audit trail and letting a prefix scope match only the
 * spelling the caller chose. The over-approximation costs a POSIX file whose
 * name literally contains `\` one extra path level in its resource.
 */
function normalizeFsPath(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) return null;
  const segments = value.split(/[/\\]+/).filter((s) => s.length > 0);
  if (segments.length === 0) return null;
  // PKA-157/159/190: FOLD `.` and in-bounds `..` rather than refusing them.
  //
  // This used to refuse any path containing either segment. Refusing is safe
  // for `../../etc/passwd` but wrong for `./a/b`, which is an ordinary relative
  // path — and refusing ordinary work is what pushed operators to
  // `unmapped_verdict: "allow"`, which is how the refusal became the PKA-159
  // bypass. Over-strictness was not free.
  //
  // Folding also fixes resource identity: `/a/b` and `/a/x/../b` are the same
  // file and must produce the same resource, or an operator rule (or an audit
  // query) written against one spelling silently misses the other.
  //
  // Escape above the root still refuses — there is no correct resource for it,
  // and emitting one would name a file outside the prefix it textually sits
  // under. The check runs on the FOLDED result, so `/a/../..` is caught.
  const folded: string[] = [];
  for (const s of segments) {
    if (s === ".") continue;
    if (s === "..") {
      if (folded.length === 0) return null; // escapes above the root
      folded.pop();
      continue;
    }
    folded.push(s);
  }
  if (folded.length === 0) return null; // normalized away to nothing
  return folded.join("/");
}

/**
 * Resource for ONE filesystem path argument: the sensitive overlay first
 * (`secret/<kind>`), else `fs/<normalized path>`; null when the path does
 * not normalize. Shared with the JSON-RPC method policy (methods.ts) so a
 * `resources/read` file URI classifies exactly like a tool path argument.
 */
export function fsPathResource(value: unknown): string | null {
  const norm = normalizeFsPath(value);
  if (norm === null) return null;
  return classifySensitivePath(norm) ?? `fs/${norm}`;
}

const INVALID: unique symbol = Symbol("invalid-segment");

/**
 * One target resource segment (github owner/repo, slack channel).
 * `undefined` = absent (reads may degrade per the hooks' scope rules);
 * INVALID = present but malformed — never guessed around: separators would
 * splice resource levels and `.`/`..` are traversal.
 */
function readSegment(value: unknown): string | undefined | typeof INVALID {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0) return INVALID;
  if (value.includes("\0") || value.includes("/")) return INVALID;
  if (value === "." || value === "..") return INVALID;
  return value;
}

// ---------------------------------------------------------------------------
// filesystem family (mirrors vinctor-claude-code-hook
// src/classifiers/mcp/filesystem.ts). Canon resources: fs/<path>, with the
// sensitive-path overlay classifying credential material as secret/<kind>.
// ---------------------------------------------------------------------------

const FILESYSTEM_TOOL_ACTIONS: Record<string, Action> = {
  read_text_file: "read",
  read_file: "read", // deprecated alias of read_text_file
  read_media_file: "read",
  read_multiple_files: "read", // one read per distinct resource (PKA-148, see below)
  list_directory: "read",
  list_directory_with_sizes: "read",
  directory_tree: "read",
  search_files: "read",
  get_file_info: "read",
  list_allowed_directories: "read",
  write_file: "write",
  edit_file: "write",
  create_directory: "write",
  move_file: "write",
  delete_file: "delete", // fork-compat (canonical server has no delete)
  delete_directory: "delete",
  remove_directory: "delete", // canon/spec name; delete_directory is the fork alias
};

function mapFilesystem(tool: string, args: Record<string, unknown>): MapResult {
  const action = ownEntry(FILESYSTEM_TOOL_ACTIONS, tool);
  if (action === undefined) return null;
  if (tool === "list_allowed_directories") {
    return { action: "read", resource: "fs/_allowed-dirs" };
  }
  if (tool === "read_multiple_files") {
    // PKA-148: N paths are N read effects. The old shape returned the FIRST
    // credential-shaped path as the whole required set, so a grant covering
    // any one member of the list read every other member — enforced,
    // permitted, and absent from the audit record — and all-ordinary lists
    // unmapped outright because one pair could not express them. Same
    // alsoRequires machinery as move_file; the proxy's gateChecks already
    // denies unless EVERY pair permits.
    //
    // Every member must normalize or the whole call unmaps (deny fail-closed):
    // charging the expressible subset would authorize a call that still reads
    // the inexpressible path. That was already this mapper's behavior; the
    // canon's unnormalizable-member vector now pins it across all adapters.
    //
    // The PRIMARY pair stays the pair the old behavior charged — the first
    // credential-shaped path, else the first path — so canon comparisons and
    // existing grants keep working. Paths folding to the same resource are
    // one requirement (the set tracks distinct effects, not list length).
    const paths = args["paths"];
    if (!Array.isArray(paths) || paths.length === 0) return PARSE_UNSAFE;
    const resources: string[] = [];
    for (const p of paths) {
      const resource = fsPathResource(p);
      if (resource === null) return PARSE_UNSAFE;
      if (!resources.includes(resource)) resources.push(resource);
    }
    const primary = resources.find((r) => r.startsWith("secret/")) ?? resources[0]!;
    const also = resources
      .filter((r) => r !== primary)
      .map((resource) => ({ action, resource }));
    return also.length > 0 ? { action, resource: primary, alsoRequires: also } : { action, resource: primary };
  }
  if (tool === "move_file") {
    // Both endpoints must be resolvable (never move an ambiguous target).
    // The PRIMARY pair stays canon/hook-compatible: a sensitive endpoint
    // classifies over secret/<kind> — the source first (moving a credential
    // away still operates on the credential), then the destination;
    // otherwise the resource is the destination, where new state appears.
    //
    // PKA-100: the primary pair alone let a file be moved OUT of a protected
    // subtree under a grant covering only the destination. A move is three
    // effects — the source is disclosed at a new location (read) and removed
    // (delete), the destination gains state (write) — so alsoRequires carries
    // every per-endpoint check the primary pair does not already assert; the
    // proxy denies unless ALL of them permit.
    const sourceRes = fsPathResource(args["source"]);
    const destinationRes = fsPathResource(args["destination"]);
    if (sourceRes === null || destinationRes === null) return PARSE_UNSAFE;
    const pick = (r: string): string | null => (r.startsWith("secret/") ? r : null);
    const primary = pick(sourceRes) ?? pick(destinationRes) ?? destinationRes;
    const also: { action: Action; resource: string }[] = [];
    const require = (a: Action, resource: string): void => {
      if (a === action && resource === primary) return; // asserted by the primary pair
      if (also.some((c) => c.action === a && c.resource === resource)) return;
      also.push({ action: a, resource });
    };
    require("read", sourceRes);
    require("delete", sourceRes);
    require(action, destinationRes); // action is "write" for move_file
    return { action, resource: primary, alsoRequires: also };
  }
  const resource = fsPathResource(args["path"]);
  if (resource === null) return PARSE_UNSAFE;
  return { action, resource };
}

// ---------------------------------------------------------------------------
// github family (mirrors vinctor-claude-code-hook
// src/classifiers/mcp/github.ts). Canon kinds: pr, issue, workflow, release,
// contents, secret — the canon collapses file/code/branch into `contents`.
// Kinds beyond the canon (collaborator, repo, fork, security, context) cover
// operations the v1 canon deliberately omits; they remain adapter policy.
// ---------------------------------------------------------------------------

type GithubKind =
  | "contents" | "release" | "collaborator" | "repo"
  | "fork" | "issue" | "pr" | "workflow" | "security" | "secret" | "context";
// PKA-150: `namespace` is a write INTO a namespace (create a repo there) —
// github/<owner>/_/repo, the 4-segment form with the repo slot set to the `_`
// sentinel and the `repo` kind. Owner comes from `organization`, not a repo.
type GithubScope = "repo" | "owner" | "global" | "flex" | "namespace";

type GithubDesc = {
  readonly action: Action | "method";
  readonly kind: GithubKind;
  readonly scope: GithubScope;
  readonly methods?: Record<string, Action>;
};

// descriptor builders (scope defaults to "repo")
const r = (kind: GithubKind, scope: GithubScope = "repo"): GithubDesc => ({ action: "read", kind, scope });
const w = (kind: GithubKind, scope: GithubScope = "repo"): GithubDesc => ({ action: "write", kind, scope });
const d = (kind: GithubKind, scope: GithubScope = "repo"): GithubDesc => ({ action: "delete", kind, scope });

const GITHUB_TOOL_TABLE: Record<string, GithubDesc> = {
  // context / users / search
  get_me: r("context", "global"),
  get_teams: r("context", "global"),
  get_team_members: r("context", "owner"),
  search_users: r("context", "global"),
  search_repositories: r("repo", "global"),
  search_code: r("contents", "global"),
  search_commits: r("contents", "global"),

  // repos / git — the canon collapses file/code/branch kinds into `contents`
  get_file_contents: r("contents"),
  get_repository_tree: r("contents"),
  list_commits: r("contents"),
  get_commit: r("contents"),
  list_branches: r("contents"),
  list_tags: r("contents"),
  get_tag: r("contents"),
  list_releases: r("release"),
  get_latest_release: r("release"),
  get_release_by_tag: r("release"),
  get_release: r("release"), // canon name (classic server)
  list_repository_collaborators: r("collaborator"),
  create_or_update_file: w("contents"),
  push_files: w("contents"),
  create_branch: w("contents"),
  delete_file: d("contents"),
  // PKA-150: creating a repository is a write into a NAMESPACE, not the old
  // namespace-less global github/_/repo. Owner comes from `organization`.
  create_repository: w("repo", "namespace"),
  // PKA-149: fork_repository is multi-effect — special-cased in mapGithub. The
  // descriptor names its PRIMARY pair (the source fork).
  fork_repository: w("fork"),

  // releases — publishing is externally effective → deploy (canon)
  create_release: { action: "deploy", kind: "release", scope: "repo" },
  publish_release: { action: "deploy", kind: "release", scope: "repo" },

  // issues
  issue_read: r("issue"),
  get_issue: r("issue"), // canon name (classic server)
  list_issues: r("issue"),
  search_issues: r("issue", "flex"),
  list_issue_types: r("issue", "owner"),
  issue_write: w("issue"),
  update_issue: w("issue"), // canon name (classic server)
  add_issue_comment: w("issue"),
  sub_issue_write: w("issue"),
  create_issue: w("issue"),
  update_issue_title: w("issue"),
  update_issue_body: w("issue"),
  update_issue_assignees: w("issue"),
  update_issue_labels: w("issue"),
  update_issue_milestone: w("issue"),
  update_issue_type: w("issue"),
  update_issue_state: w("issue"),
  add_sub_issue: w("issue"),
  remove_sub_issue: w("issue"),
  reprioritize_sub_issue: w("issue"),
  set_issue_fields: w("issue"),

  // pull_requests
  pull_request_read: r("pr"),
  get_pull_request: r("pr"), // canon name (classic server)
  list_pull_requests: r("pr"),
  search_pull_requests: r("pr", "flex"),
  create_pull_request: w("pr"),
  update_pull_request: w("pr"),
  update_pull_request_branch: w("pr"),
  pull_request_review_write: w("pr"),
  add_comment_to_pending_review: w("pr"),
  add_reply_to_pull_request_comment: w("pr"),
  // Canon: write + becomes shipping baseline → deploy by precedence (the
  // deploy moment is the merge).
  merge_pull_request: { action: "deploy", kind: "pr", scope: "repo" },
  update_pull_request_title: w("pr"),
  update_pull_request_body: w("pr"),
  update_pull_request_state: w("pr"),
  update_pull_request_draft_state: w("pr"),
  request_pull_request_reviewers: w("pr"),
  create_pull_request_review: w("pr"),
  submit_pending_pull_request_review: w("pr"),
  delete_pending_pull_request_review: w("pr"),
  add_pull_request_review_comment: w("pr"),

  // actions
  actions_list: r("workflow"),
  actions_get: r("workflow"),
  get_job_logs: r("workflow"),
  actions_run_trigger: {
    action: "method", kind: "workflow", scope: "repo",
    methods: {
      run_workflow: "execute",
      rerun_workflow_run: "execute",
      rerun_failed_jobs: "execute",
      cancel_workflow_run: "write",
      delete_workflow_run_logs: "delete",
    },
  },
  // deprecated workflow read aliases
  list_workflows: r("workflow"),
  list_workflow_runs: r("workflow"),
  list_workflow_jobs: r("workflow"),
  list_workflow_run_artifacts: r("workflow"),
  get_workflow: r("workflow"),
  get_workflow_run: r("workflow"),
  get_workflow_job: r("workflow"),
  get_workflow_run_usage: r("workflow"),
  get_workflow_run_logs: r("workflow"),
  get_workflow_job_logs: r("workflow"),
  download_workflow_run_artifact: r("workflow"),
  // deprecated workflow action aliases (single-purpose)
  run_workflow: { action: "execute", kind: "workflow", scope: "repo" },
  rerun_workflow_run: { action: "execute", kind: "workflow", scope: "repo" },
  rerun_failed_jobs: { action: "execute", kind: "workflow", scope: "repo" },
  cancel_workflow_run: { action: "write", kind: "workflow", scope: "repo" },
  delete_workflow_run_logs: { action: "delete", kind: "workflow", scope: "repo" },

  // code_security / dependabot
  get_code_scanning_alert: r("security"),
  list_code_scanning_alerts: r("security"),
  get_dependabot_alert: r("security"),
  list_dependabot_alerts: r("security"),

  // secret_protection — canon kind `secret` under the repo scope
  get_secret_scanning_alert: r("secret"),
  list_secret_scanning_alerts: r("secret"),
};

function mapGithub(tool: string, args: Record<string, unknown>): MappedCall | null {
  const desc = ownEntry(GITHUB_TOOL_TABLE, tool);
  if (desc === undefined) return null;

  let action: Action;
  if (desc.action === "method") {
    const method = args["method"];
    const dispatched =
      typeof method === "string" && desc.methods !== undefined
        ? ownEntry(desc.methods, method)
        : undefined;
    if (dispatched === undefined) return null;
    action = dispatched;
  } else {
    action = desc.action;
  }

  const owner = readSegment(args["owner"]);
  const repo = readSegment(args["repo"]);
  if (owner === INVALID || repo === INVALID) return null; // never guess a malformed target
  const kind = desc.kind;
  const isRead = action === "read";

  // PKA-149: fork_repository is three effects, not one. The primary is the
  // source fork (both owner AND repo must be present — never fork an ambiguous
  // source), unchanged so existing fork grants keep working. It ALSO reads the
  // source repo's contents (a fork copies them) and writes a NEW repository into
  // the destination namespace named by `organization` (PKA-150 form). Charging
  // only the source fork let a fork grant on acme/api create a repository — and
  // a copy of its contents — inside an org the operator never authorized; the
  // proxy denies unless ALL pairs permit.
  if (tool === "fork_repository") {
    if (owner === undefined || repo === undefined) return null;
    const dest = destinationNamespace(args);
    if (dest === INVALID) return null; // a malformed org is never guessed around
    return {
      action,
      resource: `github/${owner}/${repo}/fork`,
      alsoRequires: [
        { action: "read", resource: `github/${owner}/${repo}/contents` },
        { action: "write", resource: `github/${dest}/_/repo` },
      ],
    };
  }

  switch (desc.scope) {
    case "global":
      return { action, resource: `github/_/${kind}` };
    case "namespace": {
      // PKA-150: a write INTO a namespace. Degrades to the coarse github/_/_/repo
      // when the namespace is unknown, never to nothing — a create still makes a
      // repo SOMEWHERE.
      const dest = destinationNamespace(args);
      if (dest === INVALID) return null;
      return { action, resource: `github/${dest}/_/${kind}` };
    }
    case "owner":
      if (owner !== undefined) return { action, resource: `github/${owner}/_/${kind}` };
      if (isRead) return { action, resource: `github/_/${kind}` };
      return null;
    case "flex":
      if (owner !== undefined && repo !== undefined) {
        return { action, resource: `github/${owner}/${repo}/${kind}` };
      }
      if (owner !== undefined) return { action, resource: `github/${owner}/_/${kind}` };
      return { action, resource: `github/_/${kind}` };
    case "repo":
      if (owner !== undefined && repo !== undefined) {
        return { action, resource: `github/${owner}/${repo}/${kind}` };
      }
      if (isRead) {
        return { action, resource: owner !== undefined ? `github/${owner}/_/${kind}` : `github/_/${kind}` };
      }
      return null; // never mutate an ambiguous target
  }
  return null;
}

/**
 * The owner segment of a namespace-write resource (github/<owner>/_/repo): the
 * `organization` arg. Absent means the caller's own account, which the proxy
 * cannot name, so it degrades to the deliberately-coarse `_` — an operator who
 * wants to allow that grants github/_/_/repo explicitly. A malformed value is
 * INVALID (never guessed around), consistent with this mapper's owner/repo
 * handling. Never guessed from the source owner: a fork into acme's own org is
 * a different grant from a fork into the agent's account.
 */
function destinationNamespace(args: Record<string, unknown>): string | typeof INVALID {
  const org = readSegment(args["organization"]);
  if (org === INVALID) return INVALID;
  return org ?? "_";
}

// ---------------------------------------------------------------------------
// slack family (mirrors vinctor-claude-code-hook
// src/classifiers/mcp/slack.ts). Canon resource grammar: chat/slack/<channel>;
// workspace-scoped operations bind the platform prefix chat/slack.
// ---------------------------------------------------------------------------

type SlackScope = "channel" | "workspace" | "search";
type SlackDesc = { readonly action: Action; readonly scope: SlackScope };

const sread = (scope: SlackScope): SlackDesc => ({ action: "read", scope });
const ssend = (scope: SlackScope): SlackDesc => ({ action: "send", scope });

const SLACK_TOOL_TABLE: Record<string, SlackDesc> = {
  // reference @modelcontextprotocol/server-slack (slack_*) + Zencoder fork
  slack_list_channels: sread("workspace"),
  slack_get_users: sread("workspace"),
  slack_get_user_profile: sread("workspace"),
  slack_get_channel_history: sread("channel"),
  slack_get_thread_replies: sread("channel"),
  slack_post_message: ssend("channel"),
  slack_reply_to_thread: ssend("channel"),
  slack_add_reaction: ssend("channel"),

  // korotovsky slack-mcp-server
  channels_list: sread("workspace"),
  channels_me: sread("workspace"),
  conversations_unreads: sread("workspace"),
  users_search: sread("workspace"),
  conversations_history: sread("channel"),
  conversations_replies: sread("channel"),
  conversations_search_messages: sread("search"),
  conversations_add_message: ssend("channel"),
  conversations_join: ssend("channel"),
  conversations_leave: ssend("channel"),
  conversations_mark: ssend("channel"),
  reactions_add: ssend("channel"),
  reactions_remove: ssend("channel"),
};

function mapSlack(tool: string, args: Record<string, unknown>): MappedCall | null {
  const desc = ownEntry(SLACK_TOOL_TABLE, tool);
  if (desc === undefined) return null;
  const { action } = desc;

  switch (desc.scope) {
    case "workspace":
      return { action, resource: "chat/slack" };
    case "channel": {
      const channel = readSegment(args["channel_id"]);
      if (channel === INVALID) return null; // never guess a malformed target
      if (channel !== undefined) return { action, resource: `chat/slack/${channel}` };
      if (action === "send") return null; // never send to an ambiguous target
      return { action, resource: "chat/slack" };
    }
    case "search": {
      const channel = readSegment(args["filter_in_channel"]);
      if (channel === INVALID) return null;
      return { action, resource: channel !== undefined ? `chat/slack/${channel}` : "chat/slack" };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

type Family = {
  readonly server: string;
  readonly has: (tool: string) => boolean;
  readonly map: (tool: string, args: Record<string, unknown>) => MapResult;
};

const FAMILIES: readonly Family[] = [
  { server: "filesystem", has: (t) => ownEntry(FILESYSTEM_TOOL_ACTIONS, t) !== undefined, map: mapFilesystem },
  { server: "github", has: (t) => ownEntry(GITHUB_TOOL_TABLE, t) !== undefined, map: mapGithub },
  { server: "slack", has: (t) => ownEntry(SLACK_TOOL_TABLE, t) !== undefined, map: mapSlack },
];

export function mapToolCall(name: string, args: Record<string, unknown>): MapResult {
  const parsed = parseToolName(name);
  if (parsed === null) return null;
  const { server, tool } = parsed;

  if (server !== null) {
    const family = FAMILIES.find((f) => f.server === server);
    return family === undefined ? null : family.map(tool, args);
  }

  // Bare tool name: map only when exactly ONE family claims it. `delete_file`
  // is both a filesystem-fork tool and a classic GitHub tool; args are
  // caller-controlled, so guessing the family from arg shape could enforce
  // against the wrong family's resource tree. Ambiguous bare names stay
  // unmapped (the proxy denies fail-closed); the prefixed spellings are the
  // unambiguous forms.
  const claims = FAMILIES.filter((f) => f.has(tool));
  const only = claims[0];
  if (claims.length !== 1 || only === undefined) return null;
  return only.map(tool, args);
}
