/**
 * C11 — ReDoS: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 *
 * NOTE: This rule analyses regex *patterns*. The pattern strings the
 * analyser examines are NOT regex literals in this file — they are
 * data being walked character-by-character by the structural pattern
 * analyser in gather.ts.
 */

/** Linear-time engine names whose presence in source signals mitigation. */
export const LINEAR_TIME_ENGINE_NAMES: ReadonlySet<string> = new Set([
  "RE2",
  "re2",
  "node-re2",
  "Hyperscan",
]);

/** Identifier names for length-bounded checks. */
export const LENGTH_BOUND_TOKENS: ReadonlySet<string> = new Set([
  "maxLength",
  "MAX_LENGTH",
  "MAX_INPUT_LENGTH",
  "substring",
  "substr",
  "slice",
]);
