/**
 * K7 expiry-property vocabulary.
 *
 * Property NAMES that configure token lifetime. When the rule walks
 * CallExpression arguments (token creation call) or top-level
 * ObjectLiteralExpression properties, presence of any of these names on
 * a property key indicates the expiry surface.
 *
 * Two classes:
 *
 *   - EXPIRY_DURATION_PROPERTIES — set to a duration value (string or
 *     number). Value is parsed and compared to MAX_ACCESS/REFRESH
 *     thresholds defined in the charter.
 *
 *   - EXPIRY_DISABLE_PROPERTIES — when set to `true`/`false` depending
 *     on sense, disable expiration enforcement entirely.
 */

/** Property names carrying a duration value. */
export const EXPIRY_DURATION_PROPERTIES: Record<string, true> = {
  expiresin: true,
  expires_in: true,
  maxage: true,
  max_age: true,
  token_lifetime: true,
  tokenlifetime: true,
  lifetime: true,
  ttl: true,
  exp: true,
  duration: true,
  validfor: true,
  valid_for: true,
  expirydays: true,
  expiry_days: true,
};

/**
 * Property names that toggle expiration enforcement. `disabledValue` is
 * the literal value that — when assigned — REMOVES the expiration check.
 * The rule's classifier compares the assigned literal (boolean, null,
 * undefined, or number 0) to this field.
 */
export const EXPIRY_DISABLE_PROPERTIES: Record<string, "true" | "false" | "zero-or-null"> = {
  ignoreexpiration: "true",
  ignore_expiration: "true",
  verify: "false",
  verifyexpiration: "false",
  validateexp: "false",
  validateexpiry: "false",
  checkexpiration: "false",
  expiresin: "zero-or-null",
  maxage: "zero-or-null",
};

/**
 * Duration-unit suffix → seconds multiplier. Used by the character-level
 * parser in gather-ast.ts to convert "365d", "24h", "1y" to seconds.
 */
export const DURATION_UNIT_SECONDS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
  w: 604800,
  y: 31536000,
};

/** Milliseconds suffix handled separately (divide by 1000). */
export const MS_SUFFIXES: Record<string, true> = {
  ms: true,
};

/**
 * Thresholds (in seconds) that separate an acceptable lifetime from a
 * long-lived one. From OAuth 2.1 BCP + RFC 9700 + ISO 27001 A.8.24
 * implementation guidance (24h access token, 30d refresh token).
 *
 *   - ACCESS_TOKEN: 24h. Any `expiresIn` > 24h on a token-creation call
 *     is flagged as "excessive-expiry (access class)".
 *   - REFRESH_TOKEN: 30d. When the rule can infer that the call is for a
 *     refresh token (property name `refresh_expires_in`, receiver
 *     containing "refresh"), it uses this threshold instead.
 */
export const MAX_ACCESS_TOKEN_SECONDS = 86400;
export const MAX_REFRESH_TOKEN_SECONDS = 2592000;
