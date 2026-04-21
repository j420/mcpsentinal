/**
 * L6 — Config Directory Symlink Attack: vocabularies.
 *
 * Lives under `data/` (guard-skipped). Zero regex literals.
 */

/**
 * Substrings that identify a sensitive target path. The symlink-
 * creation detector compares the symlink target argument against this
 * list; a hit marks the finding as "creation-to-sensitive-path".
 */
export const SENSITIVE_TARGET_PATHS: ReadonlySet<string> = new Set([
  "/etc/passwd",
  "/etc/shadow",
  "/etc/sudoers",
  "/etc/hosts",
  "/etc/ssh",
  "/root",
  "/root/.ssh",
  "/proc",
  "/sys",
  "/var/run/secrets",
  "~/.ssh",
  "~/.aws",
  "~/.gnupg",
  "~/.docker/config.json",
  ".claude/settings.json",
  ".cursor/mcp.json",
  ".gemini",
  ".mcp.json",
  ".env",
  ".env.local",
]);

/**
 * Callee identifiers that create a symlink. The walker looks for
 * PropertyAccess `fs.<name>` / `fsp.<name>` / `os.<name>` and the
 * bare identifier form for os.symlink (Python shape after decl flow).
 */
export const SYMLINK_CREATE_CALLEES: ReadonlySet<string> = new Set([
  "symlink",
  "symlinkSync",
]);

/** Read-side file I/O callees we inspect for symlink-guard mitigations. */
export const READ_CALLEES: ReadonlySet<string> = new Set([
  "readFile",
  "readFileSync",
  "open",
  "openSync",
  "createReadStream",
  "readlink",
  "readlinkSync",
]);

/** Symlink-aware guard callees that, when present in the same scope, count as mitigation. */
export const SYMLINK_GUARD_CALLEES: ReadonlySet<string> = new Set([
  "realpath",
  "realpathSync",
  "lstat",
  "lstatSync",
]);

/** Flags that, when present as a literal in the call arguments, indicate the NOFOLLOW mitigation. */
export const NOFOLLOW_FLAG_TOKENS: readonly string[] = [
  "O_NOFOLLOW",
  "AT_SYMLINK_NOFOLLOW",
  "fs.constants.O_NOFOLLOW",
  "RESOLVE_NO_SYMLINKS",
] as const;

/**
 * Substrings that identify an attacker-reachable config directory. A
 * symlink CREATION whose link-path argument contains one of these
 * substrings is escalated (placing a malicious symlink inside a
 * downstream agent's config).
 */
export const ATTACKER_REACHABLE_CONFIG_DIRS: ReadonlySet<string> = new Set([
  ".claude",
  ".cursor",
  ".gemini",
  ".mcp",
  "mcp.json",
  ".claude.json",
  ".vscode",
]);
