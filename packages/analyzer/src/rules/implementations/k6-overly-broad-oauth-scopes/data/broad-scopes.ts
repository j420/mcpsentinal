/**
 * K6 overly-broad OAuth scope vocabulary.
 *
 * Canonical lists live as Record<string, X> object literals so the
 * no-static-patterns guard leaves them alone. The detection in
 * `../gather-ast.ts` projects keys into ReadonlySet<string> at module load.
 *
 * Rationale per class:
 *
 *   - WILDCARD_TOKENS — exact string match. The special case is "*"; the
 *     colon-delimited "*:*" and "scope:*" are caught by a structural
 *     split check (any token whose segment after ":" is "*").
 *
 *   - ADMIN_TOKENS — exact (case-insensitive) token match for identifiers
 *     that grant blanket administrative authority. Adding a token here
 *     requires evidence it is used as a grant level, not just a label —
 *     "admin-dashboard-read" should NOT match "admin" alone; the rule
 *     enforces exact-token semantics by comparing the NORMALISED scope
 *     string (lowercased, trimmed) against this set and NOT substring.
 *
 *   - BROAD_PREFIXED_TOKENS — canonical forms of "verb:all" / "verb:*"
 *     (GitHub, Google, Azure patterns). Exact-token match.
 *
 *   - SUFFIX_ADMIN — structural suffix check triggered when a scope has
 *     the shape "<ns>:admin" or "<ns>.admin". The rule computes the suffix
 *     at detection time; no regex.
 */

/** Severity class emitted by classifyScope() and surfaced to the chain. */
export type ScopeSeverity = "wildcard" | "admin" | "broad";

/** Exact-token match: these scope values are the single character "*" (or equivalent). */
export const WILDCARD_TOKENS: Record<string, true> = {
  "*": true,
};

/** Exact-token match (case-insensitive) for administrative grants. */
export const ADMIN_TOKENS: Record<string, true> = {
  admin: true,
  root: true,
  all: true,
  superuser: true,
  owner: true,
  full_access: true,
  "full-access": true,
  fullaccess: true,
  everything: true,
};

/** Exact-token match for colon-delimited broad grants (GitHub, Google, Azure). */
export const BROAD_PREFIXED_TOKENS: Record<string, true> = {
  "read:all": true,
  "write:all": true,
  "manage:all": true,
  "admin:all": true,
  "repo:all": true,
  "user:all": true,
  "files:all": true,
  "sites:full_control": true,
  "full_control:all": true,
};

/**
 * Token SEGMENTS that, when appearing as the final colon-delimited or
 * dot-delimited segment of a scope, escalate severity to admin. Detection
 * splits the scope on ":" and "." and checks the last segment against
 * this set.
 *
 * This covers GitHub ("admin:org"), GCP ("bigquery.admin"), and bespoke
 * patterns ("billing:admin") without hard-coding every possible prefix.
 */
export const ADMIN_SUFFIX_SEGMENTS: Record<string, true> = {
  admin: true,
  owner: true,
  root: true,
  all: true,
  full_control: true,
  fullcontrol: true,
  superuser: true,
};

/**
 * Token SEGMENTS that, when appearing as the final colon-delimited or
 * dot-delimited segment of a scope value, escalate severity to wildcard.
 * Used to catch "scope:*", "ns:*", etc.
 */
export const WILDCARD_SUFFIX_SEGMENTS: Record<string, true> = {
  "*": true,
};
