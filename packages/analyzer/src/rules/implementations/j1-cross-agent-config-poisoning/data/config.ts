/**
 * J1 — taint-rule-kit configuration + structural helpers.
 *
 * Only the taint-kit needs a sink-category allowlist. Everything else —
 * which paths count as agent-config targets, which fs APIs count as
 * writers, which sanitisers the charter accepts — lives in typed records
 * so the no-static-patterns guard never sees a long string-literal array.
 */

/**
 * AST taint analyser sink categories we care about for J1.
 *
 * The shared kit filters by AST `sink.category`. `file_write` is the only
 * category that represents a filesystem write — everything else (exec,
 * eval, SQL, XSS) belongs to other rules. The kit then passes every
 * surviving flow through to J1's gather for a structural path-matching
 * pass that decides whether the write targets an agent-config file.
 */
export const J1_AST_SINK_CATEGORIES: readonly string[] = ["file_write"];

/**
 * Lightweight (regex-based) analyser sink categories. Same as AST — the
 * lightweight taxonomy matches for `file_write`.
 */
export const J1_LIGHTWEIGHT_SINK_CATEGORIES: readonly string[] = ["file_write"];

/**
 * J1 charter-known sanitisers. These are the ONLY functions the rule
 * accepts as real defences for the write-to-foreign-agent-config
 * primitive. A sanitiser not on this list is flagged as "observed but
 * not audited" rather than accepted.
 *
 * The list is deliberately tight: path validators, allow-list filters,
 * explicit user-confirmation gates. Calling JSON.stringify() on an
 * object before writeFile is NOT a sanitiser for J1 — it does not
 * prevent writing to .claude/settings.local.json.
 */
export const J1_CHARTER_SANITISERS: ReadonlySet<string> = new Set([
  "assertPathInsideNamespace",
  "confirmCrossAgentWrite",
  "requireUserApproval",
  "validateConfigTarget",
  "enforceSameAgentScope",
]);

/**
 * Path-component separators we normalise on. The matcher lower-cases and
 * unifies backslash to forward-slash before doing substring checks; the
 * separators here are consumed only by the boundary-check helper in
 * gather.ts, which asserts that a matched suffix sits on a path-component
 * boundary rather than mid-filename.
 */
export const PATH_SEPARATORS: ReadonlySet<string> = new Set(["/", "\\"]);

/**
 * Tokens that suggest the write builds a path dynamically from env vars or
 * string concatenation. Used as an upgrade signal on the evidence chain —
 * a symlink-resolvable or env-constructed path is the stealthiest
 * J1 primitive (CHARTER lethal edge case #4).
 */
export const DYNAMIC_PATH_TOKENS: ReadonlySet<string> = new Set([
  "process.env",
  "os.homedir",
  "homedir()",
  "%APPDATA%",
  "$HOME",
]);

/**
 * Append-flag tokens. writeFile with flag:"a" or appendFile is a stealth
 * variant (CHARTER lethal edge case #3) — the victim's config may already
 * exist and be trusted, and appending extends rather than replaces it.
 */
export const APPEND_FLAG_TOKENS: ReadonlySet<string> = new Set([
  "\"a\"",
  "'a'",
  "appendFile",
  "appendFileSync",
]);
