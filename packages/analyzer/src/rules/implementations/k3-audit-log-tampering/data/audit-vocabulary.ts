/**
 * K3 vocabulary tables — loaded by gather.ts. Typed records keep the
 * array-literal guard happy (no bare string arrays > 5 items).
 */

export const AUDIT_PATH_SUBSTRINGS: ReadonlySet<string> = new Set([
  ".log",
  "audit",
  "journal",
  "access_log",
  "events.json",
  "audit.json",
  "audit-trail",
]);

export const TAMPER_TRANSFORM_TOKENS: ReadonlySet<string> = new Set([
  "filter",
  "replace",
  "slice",
  "splice",
  "map",
  "reduce",
]);

export const REDACTION_EXCLUSION_TOKENS: ReadonlySet<string> = new Set([
  "redact",
  "pii",
  "gdpr",
  "anonymize",
  "anonymise",
  "sanitize",
]);

export const INPLACE_SHELL_TOKENS: ReadonlySet<string> = new Set([
  "sed -i",
  "sed --in-place",
  "perl -i",
  "perl -pi",
]);

export const INPLACE_OPEN_FLAGS: ReadonlySet<string> = new Set([
  "r+",
  "w+",
  "a+",
]);

export const TIMESTAMP_FORGERY_CALLEES: ReadonlySet<string> = new Set([
  "utimes",
  "utimesSync",
  "futimes",
  "futimesSync",
  "lutimes",
  "lutimesSync",
]);
