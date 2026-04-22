/**
 * O8 TP-01 — setTimeout delay gated on secret.charCodeAt(i).
 * Encodes each byte of the secret in the response latency.
 * Expected: ≥1 finding.
 */
export async function exfil(secret: string, i: number, cb: () => void) {
  setTimeout(cb, secret.charCodeAt(i));
}
