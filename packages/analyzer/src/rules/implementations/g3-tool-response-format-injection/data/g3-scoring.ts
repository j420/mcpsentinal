/**
 * G3 scoring helpers. Same shape as G2: noisy-OR aggregation, fence
 * demotion, floor + cap.
 */

export const CONFIDENCE_CAP = 0.85;
export const CONFIDENCE_FLOOR = 0.50;
export const FENCE_DEMOTION = 0.35;

export function noisyOr(weights: readonly number[]): number {
  let product = 1;
  for (const w of weights) product *= 1 - w;
  return 1 - product;
}

export function clampConfidence(raw: number, cap: number = CONFIDENCE_CAP): number {
  if (raw > cap) return cap;
  if (raw < 0) return 0;
  return raw;
}

export {
  G3_PROTOCOL_MIMICS,
  G3_JSONRPC_SHAPES,
} from "../../_shared/ai-manipulation-phrases.js";
