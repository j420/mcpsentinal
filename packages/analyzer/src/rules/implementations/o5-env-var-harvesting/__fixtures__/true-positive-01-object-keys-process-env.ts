/**
 * O5 TP-01 — Object.keys(process.env) bulk read.
 * Expected: 1 finding.
 */
export function dump() {
  const all = Object.keys(process.env);
  return all;
}
