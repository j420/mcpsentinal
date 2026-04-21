/**
 * C4 — SQL Injection: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 * The exports here are plain data — no regex — feeding:
 *
 *   • sink categories the C4 rule filters the taint engines' output by;
 *   • sanitiser names the charter considers audited-safe;
 *   • the impact-scenario template the evidence chain narrative uses.
 *
 * Adding an entry: only add SQL-specific safeguards. A sanitiser for
 * shell-escape would be wrong here because it does not protect SQL.
 */

/** Sink categories reported by analyzeASTTaint that C4 treats as SQL sinks. */
export const C4_AST_SINK_CATEGORIES: readonly string[] = ["sql_injection"] as const;

/**
 * Sink categories reported by the lightweight analyzeTaint engine that C4
 * treats as SQL sinks. The taint.ts taxonomy uses "sql_query" whereas the
 * AST taint taxonomy uses "sql_injection" — gather.ts normalises by
 * passing both lists.
 */
export const C4_LIGHTWEIGHT_SINK_CATEGORIES: readonly string[] = ["sql_query"] as const;

/**
 * Charter-audited sanitiser names. When the taint analyser reports a
 * sanitiser on the path whose name IS in this set, the C4 rule drops
 * severity from critical to informational without emitting the
 * "unverified_sanitizer_identity" factor. Names NOT in this set still
 * drop severity but carry the negative factor so a reviewer audits the
 * sanitiser's body.
 */
export const C4_CHARTER_SANITISERS: ReadonlySet<string> = new Set([
  "prepare",
  "parameterize",
  "parameterise",
  "escape",
  "Number",
  "parseInt",
  "parseFloat",
  "validate",
  "zod.parse",
  "joi.validate",
  "yup.validate",
]);
