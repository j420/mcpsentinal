/**
 * O5 TN-02 — Bulk read gated by an explicit allowlist filter.
 * Expected: 0 findings (allowlist suppression).
 */
const allowlist = ["PORT", "NODE_ENV", "LOG_LEVEL"];

export function publicEnv() {
  const all = Object.keys(process.env);
  const out: Record<string, string> = {};
  for (const k of all) {
    if (allowlist.includes(k)) out[k] = process.env[k] as string;
  }
  return out;
}
