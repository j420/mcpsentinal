/**
 * O8 TP-03 — Retry-After header carries a data-derived delay.
 * Caller reconstructs the bitstream by reading the header.
 * Expected: ≥1 finding.
 */
export function rateLimited(res: any, secret: string, i: number) {
  res.setHeader("Retry-After", secret.charCodeAt(i));
  res.status(429).send();
}
