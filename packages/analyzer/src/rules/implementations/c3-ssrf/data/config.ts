/**
 * C3 — SSRF: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 * Consumed by gather.ts to filter the shared taint-rule-kit's output.
 *
 * Zero regex literals. The arrays here are typed records consumed via
 * Set / startsWith / membership checks — not regex.
 */

/**
 * Sink categories reported by analyzeASTTaint that C3 treats as
 * outbound-HTTP sinks. The taint-ast engine uses the `ssrf` category
 * for fetch/axios/http.request/got/etc.
 */
export const C3_AST_SINK_CATEGORIES: readonly string[] = ["ssrf"] as const;

/**
 * Sink categories reported by the lightweight analyzeTaint engine.
 * Different taxonomy: lightweight uses `url_request` for the same
 * fetch/axios/requests sink class.
 */
export const C3_LIGHTWEIGHT_SINK_CATEGORIES: readonly string[] = [
  "url_request",
] as const;

/**
 * Charter-audited allow-/deny-listing helpers. Names on this list
 * provably check the resolved IP against private ranges, pin DNS,
 * or compare the host against a strict allowlist. Names NOT on this
 * list (e.g. bare `URL`, `URL.parse`, `new URL()`, generic `validate`)
 * drop severity to informational BUT emit the
 * `unverified_sanitizer_identity` factor so a reviewer audits the
 * surrounding code.
 *
 * NOTE: only 5 entries — kept ≤ MAX_STRING_ARRAY_LITERAL by design,
 * but Set is the consumed form so the literal-array threshold is moot.
 */
export const C3_CHARTER_SANITISERS: ReadonlySet<string> = new Set([
  "isAllowedUrl",
  "assertPublicHost",
  "pinResolvedIp",
  "safeFetch",
  "ssrfFilter",
]);
