/**
 * O8 TP-02 — await sleep(token[i]) — per-char timing encoding of token bytes.
 * Expected: ≥1 finding.
 */
declare function sleep(ms: number): Promise<void>;

export async function drip(token: number[], i: number) {
  await sleep(token[i]);
  return "ok";
}
