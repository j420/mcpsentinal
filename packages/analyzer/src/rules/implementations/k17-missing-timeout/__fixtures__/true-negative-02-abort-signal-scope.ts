/**
 * K17 TN-02 — fetch with AbortController in the enclosing scope.
 * The two-signal detector (AbortController + `.signal`) recognises the
 * mitigation. Expected: no finding.
 */

export async function fetchWithTimeout(url: string): Promise<unknown> {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 5000);
  const res = await fetch(url, { signal: controller.signal });
  return res.json();
}
