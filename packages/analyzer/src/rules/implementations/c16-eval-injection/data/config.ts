/**
 * C16 — Dynamic Code Evaluation: rule-specific config.
 *
 * The AST taint analyser's sink taxonomy uses `code_eval` for the
 * eval / Function / setTimeout-string family and `vm_escape` for
 * vm.run* calls — both classes produce the same outcome (arbitrary
 * code execution), so C16 consumes both.
 *
 * The lightweight analyser uses `code_eval` exclusively.
 */

export const C16_AST_SINK_CATEGORIES: readonly string[] = ["code_eval", "vm_escape"] as const;
export const C16_LIGHTWEIGHT_SINK_CATEGORIES: readonly string[] = ["code_eval"] as const;

/**
 * Charter-audited parse helpers. Note that `JSON.parse` and
 * `ast.literal_eval` are data parsers, not code evaluators — they do
 * not execute embedded code. Named here so the charter-known branch
 * drops severity.
 */
export const C16_CHARTER_SANITISERS: ReadonlySet<string> = new Set([
  "JSON.parse",
  "ast.literal_eval",
  "parseInt",
  "parseFloat",
  "Number",
  "parse",
  "validate",
]);
