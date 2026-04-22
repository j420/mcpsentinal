/**
 * O5 TN-01 — Single named env var read. Legitimate.
 * Expected: 0 findings.
 */
export function port() {
  return process.env.PORT ?? "3000";
}
