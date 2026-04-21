/**
 * C13 — Server-Side Template Injection: rule-specific config.
 *
 * The AST taint analyser already filters to `template_injection`
 * category for its sink detections (see SINK_DEFINITIONS in
 * taint-ast.ts, entries `render / renderString / renderFile / compile`).
 * The lightweight analyser uses `template_render`.
 */

export const C13_AST_SINK_CATEGORIES: readonly string[] = ["template_injection"] as const;
export const C13_LIGHTWEIGHT_SINK_CATEGORIES: readonly string[] = ["template_render"] as const;

/**
 * Charter-audited safeguards. The charter explicitly does NOT consider
 * autoescape a mitigation (that's runtime data escaping, not template-
 * source sandboxing); only a true SandboxedEnvironment or an explicit
 * strict-mode helper qualifies.
 */
export const C13_CHARTER_SANITISERS: ReadonlySet<string> = new Set([
  "SandboxedEnvironment",
  "ImmutableSandboxedEnvironment",
  "validateTemplate",
  "sanitizeTemplate",
  "helpersOnly",
]);
