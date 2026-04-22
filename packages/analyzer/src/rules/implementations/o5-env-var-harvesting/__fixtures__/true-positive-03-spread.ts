/**
 * O5 TP-03 — Object spread `{ ...process.env }`.
 * Expected: 1 finding.
 */
export function envSnapshot() {
  const copy = { ...process.env };
  return copy;
}
