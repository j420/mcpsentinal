/**
 * J2 — Git Argument Injection: rule-specific config.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 */

export const J2_AST_SINK_CATEGORIES: readonly string[] = ["command_execution"] as const;
export const J2_LIGHTWEIGHT_SINK_CATEGORIES: readonly string[] = ["command_execution"] as const;

/**
 * Substrings that identify the sink call as a git invocation. If NONE of
 * these appears in the sink expression or the hop expressions leading to
 * it, the finding is discarded — J2 only fires when the sink is specifically
 * git, not generic command injection (C1's territory).
 */
export const J2_GIT_MARKERS: readonly string[] = [
  "git ",
  '"git"',
  "'git'",
  "`git ",
  "simple-git",
  "nodegit",
  "isomorphic-git",
  "git_init",
  "git.init",
  "git_diff",
] as const;

/**
 * Charter-audited git-wrapper libraries. Their presence on the path
 * drops severity to informational because these libraries validate
 * arguments (the simple-git project has a hardened-argv mode; nodegit
 * and isomorphic-git bypass shell entirely).
 */
export const J2_CHARTER_SANITISERS: ReadonlySet<string> = new Set([
  "simple-git",
  "simpleGit",
  "nodegit",
  "isomorphic-git",
  "validate",
  "validateGitRef",
  "allowlist",
]);

/**
 * Dangerous git flag signatures inside the sink expression — substrings
 * whose presence in a git call with user-controlled arguments is the
 * CVE-2025-68145 primitive.
 */
export const J2_DANGEROUS_FLAG_MARKERS: readonly string[] = [
  "--upload-pack",
  "--receive-pack",
  "--exec",
  "-c core.ssh",
  "-c core.hook",
  "-c alias.",
] as const;

/**
 * Sensitive paths that should never be passed to git_init or written to
 * by MCP servers.
 */
export const J2_SENSITIVE_PATH_MARKERS: readonly string[] = [
  ".ssh",
  ".git/config",
  ".git/hooks",
] as const;
