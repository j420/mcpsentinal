/**
 * G2 scoring helpers. The noisy-OR formula is a one-liner but
 * splitting it out of `index.ts` keeps the index file focused on
 * orchestration and lets the tests pin the math directly.
 */

export const CONFIDENCE_CAP = 0.80;
export const CONFIDENCE_FLOOR = 0.50;
/** When any fence token co-occurs, multiply the weight by this demotion. */
export const FENCE_DEMOTION = 0.35;

/**
 * Combine independent probability weights via noisy-OR:
 *
 *   P = 1 - Π(1 - wᵢ)
 *
 * Each weight is INDEPENDENT — the tokeniser emits one hit per
 * catalogue entry, and per-entry weights were calibrated to
 * non-overlapping signals.
 */
export function noisyOr(weights: readonly number[]): number {
  let product = 1;
  for (const w of weights) product *= 1 - w;
  return 1 - product;
}

/** Clamp the aggregated confidence to [floor, cap]. Floor suppresses, cap clamps. */
export function clampConfidence(raw: number, cap: number = CONFIDENCE_CAP): number {
  if (raw > cap) return cap;
  if (raw < 0) return 0;
  return raw;
}

export { G2_AUTHORITY_CLAIMS } from "../../_shared/ai-manipulation-phrases.js";
// (re-export retained for convenience; gather.ts imports directly from _shared).
