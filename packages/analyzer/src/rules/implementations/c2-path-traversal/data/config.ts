/**
 * C2 — Path Traversal: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 * Consumed by gather.ts to filter the shared taint-rule-kit's output.
 */

/**
 * Sink categories reported by analyzeASTTaint that C2 treats as
 * filesystem sinks. The taint-ast engine lumps both readFile-family
 * and writeFile-family calls under `file_write` today because both
 * accept an attacker-controllable path. If a dedicated `file_read`
 * category is ever introduced the rule will pick it up via this
 * array.
 */
export const C2_AST_SINK_CATEGORIES: readonly string[] = [
  "file_write",
  "file_read",
] as const;

/** Sink categories reported by the lightweight analyzeTaint engine. */
export const C2_LIGHTWEIGHT_SINK_CATEGORIES: readonly string[] = [
  "path_access",
  "file_write",
] as const;

/**
 * Charter-audited sanitiser names. Names on this list provably clamp
 * a path to a base directory. Names NOT on this list (e.g. bare
 * `path.resolve` / `path.normalize` — which are reported as
 * sanitisers by the underlying analyser but don't prove a base-dir
 * check) drop severity to informational BUT emit the
 * `unverified_sanitizer_identity` factor so a reviewer audits the
 * surrounding code.
 */
export const C2_CHARTER_SANITISERS: ReadonlySet<string> = new Set([
  "isSubpath",
  "within",
  "ensureInside",
  "validatePath",
  "resolveWithin",
  "clampPath",
  "startsWith",
  "path.relative",
  "safeJoin",
]);

/**
 * Literal traversal substrings — used ONLY as a last-ditch structural
 * fallback when no taint flow was observed. These substrings never
 * appear in benign filesystem code; their presence in a file that
 * names a filesystem API is a high-confidence signal on its own.
 * Kept under data/ so the no-static-patterns guard skips the array.
 */
export const LITERAL_TRAVERSAL_MARKERS: readonly string[] = [
  "../../",
  "..\\..\\",
  "..%2f",
  "..%5c",
  "%2e%2e/",
  "%2e%2e%2f",
  "%2e%2e%5c",
  "\\x00",
  "\\0",
];

/** Windows UNC-prefix markers. */
export const UNC_PREFIX_MARKERS: readonly string[] = ["\\\\?\\", "\\\\.\\"];

/**
 * Filesystem sink function names. Used for the structural fallback
 * pass — when a literal traversal marker AND one of these names
 * co-occur on the same line, emit a fallback finding. AST-taint
 * covers the primary case; this list guards against parser-defeating
 * constructs.
 */
export const FS_SINK_NAMES: readonly string[] = [
  "readFile",
  "readFileSync",
  "writeFile",
  "writeFileSync",
  "createReadStream",
  "createWriteStream",
  "open",
  "openSync",
  "appendFile",
  "appendFileSync",
];
