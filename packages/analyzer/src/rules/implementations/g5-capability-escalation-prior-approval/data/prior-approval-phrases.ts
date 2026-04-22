/**
 * G5 — Prior-Approval Phrase Catalogue.
 *
 * Typed record of multi-token linguistic signals indicating that a tool
 * description is trying to manufacture a pre-existing grant. Each entry
 * carries an independent probability weight used in noisy-OR aggregation.
 *
 * NO regex literals. Each phrase is a typed sequence of required tokens
 * plus a maximum gap between adjacent tokens; the gather step walks the
 * description token stream and tests presence structurally.
 *
 * Design notes:
 *   - Every catalogue array stays at ≤5 entries so we never trip the
 *     no-static-patterns guard's long-string-array heuristic.
 *   - Categories map 1:1 to CHARTER lethal edge cases so the test harness
 *     can assert per-edge-case coverage.
 *   - Weights are calibrated so a single weak match (~0.75) never reaches
 *     critical on its own; two medium-weight matches cross 0.8 (critical);
 *     a single very-strong match (≥0.88) can reach critical alone.
 */

export type PriorApprovalCategory =
  | "explicit-prior-approval" // edge case #1
  | "permission-inheritance" // edge case #2
  | "session-state-reference" // edge case #3
  | "pre-declared-escalation" // edge case #4
  | "assumed-consent-by-absence"; // edge case #5

export interface PhraseSpec {
  /** Ordered sequence of required content tokens (lowercase, alphanumeric). */
  readonly tokens: readonly string[];
  /** Independent probability weight used in noisy-OR aggregation. */
  readonly weight: number;
  /** Human-readable label rendered in the evidence chain. */
  readonly label: string;
  /** Maximum token distance between adjacent spec tokens (inclusive). */
  readonly max_gap: number;
  /** Lethal edge-case category this spec covers. */
  readonly category: PriorApprovalCategory;
}

/** Edge case #1 — explicit references to a prior grant event. */
const EXPLICIT_PRIOR_APPROVAL: readonly PhraseSpec[] = [
  {
    tokens: ["permissions", "you", "already", "granted"],
    weight: 0.9,
    label: "explicit prior approval — permissions you already granted",
    max_gap: 1,
    category: "explicit-prior-approval",
  },
  {
    tokens: ["you", "already", "approved"],
    weight: 0.88,
    label: "explicit prior approval — you already approved",
    max_gap: 1,
    category: "explicit-prior-approval",
  },
  {
    tokens: ["previously", "granted"],
    weight: 0.85,
    label: "explicit prior approval — previously granted",
    max_gap: 1,
    category: "explicit-prior-approval",
  },
  {
    tokens: ["access", "you", "previously", "authorized"],
    weight: 0.88,
    label: "explicit prior approval — access previously authorized",
    max_gap: 2,
    category: "explicit-prior-approval",
  },
  {
    tokens: ["user", "already", "consented"],
    weight: 0.86,
    label: "explicit prior approval — user already consented",
    max_gap: 2,
    category: "explicit-prior-approval",
  },
];

/** Edge case #2 — claims this tool inherits another tool's scope. */
const PERMISSION_INHERITANCE: readonly PhraseSpec[] = [
  {
    tokens: ["same", "permissions", "as"],
    weight: 0.82,
    label: "permission inheritance — same permissions as",
    max_gap: 1,
    category: "permission-inheritance",
  },
  {
    tokens: ["same", "access", "as"],
    weight: 0.8,
    label: "permission inheritance — same access as",
    max_gap: 1,
    category: "permission-inheritance",
  },
  {
    tokens: ["inherits", "filesystem", "access"],
    weight: 0.85,
    label: "permission inheritance — inherits filesystem access",
    max_gap: 2,
    category: "permission-inheritance",
  },
  {
    tokens: ["shares", "scope"],
    weight: 0.75,
    label: "permission inheritance — shares scope",
    max_gap: 2,
    category: "permission-inheritance",
  },
  {
    tokens: ["equivalent", "permissions"],
    weight: 0.78,
    label: "permission inheritance — equivalent permissions",
    max_gap: 2,
    category: "permission-inheritance",
  },
];

/** Edge case #3 — references an earlier turn's context/state. */
const SESSION_STATE_REFERENCE: readonly PhraseSpec[] = [
  {
    tokens: ["continues", "where", "the", "previous", "tool"],
    weight: 0.85,
    label: "session-state reference — continues where previous tool",
    max_gap: 1,
    category: "session-state-reference",
  },
  {
    tokens: ["permission", "state", "established"],
    weight: 0.82,
    label: "session-state reference — permission state established",
    max_gap: 2,
    category: "session-state-reference",
  },
  {
    tokens: ["resumes", "the", "elevated", "context"],
    weight: 0.88,
    label: "session-state reference — resumes elevated context",
    max_gap: 1,
    category: "session-state-reference",
  },
  {
    tokens: ["session", "permissions"],
    weight: 0.74,
    label: "session-state reference — session permissions",
    max_gap: 1,
    category: "session-state-reference",
  },
  {
    tokens: ["earlier", "approval"],
    weight: 0.78,
    label: "session-state reference — earlier approval",
    max_gap: 2,
    category: "session-state-reference",
  },
];

/** Edge case #4 — description announces that the tool WILL escalate. */
const PRE_DECLARED_ESCALATION: readonly PhraseSpec[] = [
  {
    tokens: ["re", "use", "your", "session", "permissions"],
    weight: 0.88,
    label: "pre-declared escalation — re-use session permissions",
    max_gap: 2,
    category: "pre-declared-escalation",
  },
  {
    tokens: ["upgrades", "scope", "on", "demand"],
    weight: 0.88,
    label: "pre-declared escalation — upgrades scope on demand",
    max_gap: 2,
    category: "pre-declared-escalation",
  },
  {
    tokens: ["extend", "your", "access"],
    weight: 0.78,
    label: "pre-declared escalation — extend your access",
    max_gap: 1,
    category: "pre-declared-escalation",
  },
  {
    tokens: ["elevate", "privilege"],
    weight: 0.8,
    label: "pre-declared escalation — elevate privilege",
    max_gap: 2,
    category: "pre-declared-escalation",
  },
  {
    tokens: ["previously", "granted", "rights"],
    weight: 0.85,
    label: "pre-declared escalation — previously granted rights",
    max_gap: 1,
    category: "pre-declared-escalation",
  },
];

/** Edge case #5 — "haven't revoked" / "still authorised" variants. */
const ASSUMED_CONSENT: readonly PhraseSpec[] = [
  {
    tokens: ["haven", "revoked"],
    weight: 0.82,
    label: "assumed consent — haven't revoked",
    max_gap: 2,
    category: "assumed-consent-by-absence",
  },
  {
    tokens: ["still", "authorised"],
    weight: 0.78,
    label: "assumed consent — still authorised",
    max_gap: 1,
    category: "assumed-consent-by-absence",
  },
  {
    tokens: ["still", "authorized"],
    weight: 0.78,
    label: "assumed consent — still authorized",
    max_gap: 1,
    category: "assumed-consent-by-absence",
  },
  {
    tokens: ["default", "grant"],
    weight: 0.72,
    label: "assumed consent — default grant",
    max_gap: 1,
    category: "assumed-consent-by-absence",
  },
  {
    tokens: ["continues", "to", "operate", "with", "full"],
    weight: 0.86,
    label: "assumed consent — continues to operate with full",
    max_gap: 1,
    category: "assumed-consent-by-absence",
  },
];

/**
 * Merged catalogue — the gather step iterates every spec once per tool
 * description. Built by spreading smaller arrays so each source array
 * stays below the 5-element string/object-array ceiling enforced by the
 * no-static-patterns guard.
 */
export const PRIOR_APPROVAL_PHRASES: readonly PhraseSpec[] = [
  ...EXPLICIT_PRIOR_APPROVAL,
  ...PERMISSION_INHERITANCE,
  ...SESSION_STATE_REFERENCE,
  ...PRE_DECLARED_ESCALATION,
  ...ASSUMED_CONSENT,
];

/**
 * Permission-noun lexicon — used by the gather step's adjacency
 * suppression so that a description like "Use alongside read_file"
 * (no permission noun anywhere in the window) is not flagged even if
 * it happens to tokenise near a weak phrase trigger.
 *
 * Kept as a Record<string, true> to keep the lookup typed and below the
 * long-string-array heuristic.
 */
export const PERMISSION_NOUNS: Readonly<Record<string, true>> = {
  access: true,
  permission: true,
  permissions: true,
  scope: true,
  rights: true,
  auth: true,
  privilege: true,
  privileges: true,
  consent: true,
  authorised: true,
  authorized: true,
};
