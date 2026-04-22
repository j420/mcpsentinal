/**
 * A5 threshold configuration. Typed record so the static-patterns guard
 * does not count it as a long string array.
 */

export const LENGTH_THRESHOLDS = {
  /** Minimum description length for A5 to fire. */
  minimum_length: 1000,
  /** Base confidence at exactly the threshold. */
  base_confidence: 0.40,
  /** Confidence increase per additional 1000 chars over threshold. */
  confidence_scale_per_kchar: 0.10,
  /** Maximum confidence achievable from length alone. */
  confidence_cap: 0.60,
} as const;
