/**
 * C15 — Timing Attack: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 */

/** Identifier names that name a server-side secret being compared. */
export const SECRET_IDENTIFIER_NAMES: ReadonlySet<string> = new Set([
  "token",
  "secret",
  "key",
  "apiKey",
  "api_key",
  "password",
  "passwd",
  "hmac",
  "hash",
  "digest",
  "signature",
  "auth",
  "authToken",
  "auth_token",
  "bearer",
  "csrf",
  "csrfToken",
  "xsrf",
  "session",
  "sessionToken",
  "session_token",
]);

/**
 * Substring fragments that indicate an identifier reads from a
 * request — used as a secondary signal for one operand of the
 * comparison.
 */
export const REQUEST_IDENTIFIER_FRAGMENTS: ReadonlySet<string> = new Set([
  "req",
  "request",
  "params",
  "body",
  "header",
  "headers",
  "query",
  "input",
  "provided",
  "supplied",
  "user",
  "client",
  "incoming",
]);

/** Method names that short-circuit on string content (timing-leaky). */
export const SHORT_CIRCUIT_METHODS: ReadonlySet<string> = new Set([
  "startsWith",
  "endsWith",
  "includes",
  "indexOf",
]);

/** Substrings whose presence in source indicates timing-safe comparison. */
export const TIMING_SAFE_MARKERS: ReadonlySet<string> = new Set([
  "timingSafeEqual",
  "compare_digest",
  "constant_time_compare",
  "secure_compare",
  "scmp.equal",
]);
