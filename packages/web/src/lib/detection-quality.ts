/**
 * Detection Quality — shared type + band thresholds.
 *
 * Cluster C part 3 (Invention #4): the per-finding footer that surfaces the
 * red-team / CVE-replay validation evidence backing a detection rule. This
 * file is the single source of truth for the precision/recall band cutoffs
 * AND the shape consumed verbatim from the API
 * (`ContractFindingResponseSchema.detection_quality`). The TS type intentionally
 * mirrors that contract exactly — agents must not infer field paths.
 *
 * Web-only module: do NOT import from `@mcp-sentinel/database` (web/CLAUDE.md
 * forbids web→database imports). The contract here is duplicated by intent.
 */

/**
 * One finding's detection-quality envelope. Shape frozen by Agent 1's
 * `DetectionQualitySchema`. Every field is explicit — no defaults inferred.
 *
 * Three states are represented purely by the field values:
 *   A. full data         → fixture_count > 0 OR cve_replay_ids.length > 0
 *   B. wired-but-empty   → fixture_count === 0 AND cve_replay_ids.length === 0
 *   C. not-wired         → the whole object is `null`
 *   D. backwards-compat  → the field is `undefined` (older API response)
 *
 * The footer component must visibly render A/B/C and stay silent on D.
 */
export interface DetectionQuality {
  /** 0..1, null when no validation runs have produced a precision metric. */
  precision: number | null;
  /** 0..1, null when no validation runs have produced a recall metric. */
  recall: number | null;
  /** Number of red-team fixtures backing the rule. 0 when none exist. */
  fixture_count: number;
  /** CVE replay corpus ids backing the rule. Empty array when none. */
  cve_replay_ids: string[];
  /** ISO 8601 timestamp of the last validation run; null when never run. */
  last_validated_at: string | null;
}

/**
 * Precision / recall display band. Maps numeric quality to a CSS color token.
 *   - good     ≥ 0.85
 *   - moderate ≥ 0.70
 *   - poor     <  0.70
 *   - unknown  null
 *
 * Cutoffs are deliberately tight at the high end: under regulator scrutiny,
 * 0.85 is the conventional "production-grade detector" threshold. Anything
 * lower is moderate at best — never green.
 */
export type QualityBand = "good" | "moderate" | "poor" | "unknown";

export const PRECISION_GOOD_MIN = 0.85;
export const PRECISION_MODERATE_MIN = 0.7;

export function bandFor(value: number | null): QualityBand {
  if (value === null) return "unknown";
  if (value >= PRECISION_GOOD_MIN) return "good";
  if (value >= PRECISION_MODERATE_MIN) return "moderate";
  return "poor";
}
