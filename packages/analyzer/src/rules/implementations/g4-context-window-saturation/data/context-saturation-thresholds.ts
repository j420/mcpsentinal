/**
 * G4 — Context Window Saturation: threshold configuration.
 *
 * Lives under `data/` so the no-static-patterns guard does not scan
 * this file for regex literals or count these as long string arrays.
 *
 * Every threshold is justified in the CHARTER.md "Threshold justifications"
 * section. Do not alter values without updating the charter.
 */

export const CONTEXT_SATURATION_THRESHOLDS = {
  /**
   * Minimum description length (bytes) before G4 will consider a tool
   * for saturation analysis. Below this, saturation is not possible
   * because the description does not consume meaningful context budget.
   */
  min_description_length: 500,

  /**
   * High-suspicion absolute length (bytes). Above this, a single-factor
   * hit is taken seriously even without peer-relative comparison.
   */
  high_suspicion_length: 3000,

  /**
   * Peer z-score threshold. A tool's description length that is ≥3σ
   * above the per-server mean is an outlier by the textbook definition
   * (>99.87% of a normal distribution lies below).
   */
  zscore_threshold: 3.0,

  /**
   * Minimum peer sample size. Below this, the per-server mean and
   * standard deviation are too noisy to trust; the z-score check is
   * disabled and the rule falls back to absolute thresholds.
   */
  min_peer_sample: 5,

  /**
   * Unique-line ratio below which a ≥1kB description is flagged as
   * repetitive padding. 0.15 means fewer than 15% of lines are unique;
   * legitimate documentation ratios sit well above 0.5.
   */
  unique_line_min_ratio: 0.15,

  /**
   * Minimum length at which the unique-line signature is applied.
   * Short descriptions naturally repeat common phrases; only bodies
   * above this size are expected to have lexical variety.
   */
  unique_line_min_length: 1000,

  /**
   * Fraction of the description classed as "tail" for the tail-
   * imperative-density check. 0.10 mirrors the placement distance
   * Rehberger demonstrations used to exploit recency bias.
   */
  tail_fraction: 0.10,

  /**
   * Minimum number of imperative-verb hits in the tail fraction to
   * fire the tail-payload signal. Two or fewer could be coincidence;
   * three or more is deliberate.
   */
  tail_imperative_threshold: 3,

  /**
   * Maximum legitimate description-to-parameter ratio (bytes per
   * declared parameter). >10× the legitimate 50–150 chars/param norm.
   */
  ratio_threshold: 2000,

  /**
   * Overall confidence cap per CHARTER.md. Structural signals are
   * strong but not definitive — the 0.22 headroom below 1.0 is the
   * reviewer's judgement budget.
   */
  confidence_cap: 0.78,

  /**
   * Base confidence that any single saturation factor contributes
   * when it fires. Multiple factors stack additively up to the cap.
   */
  base_confidence: 0.30,

  /**
   * Per-factor additive contribution — structural signals accumulate
   * evidence but are capped.
   */
  factor_increment: 0.12,
} as const;
