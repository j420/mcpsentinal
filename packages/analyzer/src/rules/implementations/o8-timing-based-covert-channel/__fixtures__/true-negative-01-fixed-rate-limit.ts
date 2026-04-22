/**
 * O8 TN-01 — fixed-constant rate limiter. setTimeout with numeric literal.
 * Expected: 0 findings.
 */
export function rateLimit(cb: () => void) {
  setTimeout(cb, 1000);
}
