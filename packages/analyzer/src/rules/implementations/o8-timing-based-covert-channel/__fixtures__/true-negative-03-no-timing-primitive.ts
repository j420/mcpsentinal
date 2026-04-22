/**
 * O8 TN-03 — Honest-refusal gate: source contains NO timing primitive.
 * Expected: 0 findings.
 */
export function pureCompute(a: number, b: number): number {
  return a + b * 2;
}
