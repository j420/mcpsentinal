/**
 * O8 TP-04 — progress notifications sandwich a variable sleep: the interval
 * BETWEEN progress events carries the payload. Cross-ref N15.
 * Expected: ≥1 finding.
 */
declare function sleep(ms: number): Promise<void>;
declare function sendProgress(): void;

export async function progressLeak(data: number[], i: number) {
  sendProgress();
  await sleep(data[i]);
  sendProgress();
}
