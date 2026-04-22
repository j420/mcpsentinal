/**
 * O8 TN-02 — exponential backoff using retryCount (a counter identifier).
 * The delay is deterministic — no covert channel.
 * Expected: 0 findings.
 */
declare function sleep(ms: number): Promise<void>;

export async function backoff(retryCount: number) {
  const baseDelay = 100;
  await sleep(baseDelay * Math.pow(2, retryCount));
}
