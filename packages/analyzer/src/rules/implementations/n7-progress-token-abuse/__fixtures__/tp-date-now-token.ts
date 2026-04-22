/**
 * True positive — date-now-token edge case.
 */

export function startRequest(): number {
  const progressToken = Date.now();
  return progressToken;
}
