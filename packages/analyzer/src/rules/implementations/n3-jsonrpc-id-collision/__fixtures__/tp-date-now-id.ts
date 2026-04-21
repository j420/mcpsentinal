/**
 * True positive — timestamp used as request id. Looks random to a human
 * reviewer; actually millisecond-predictable and monotonic.
 */

export function buildRequest(method: string): unknown {
  return { jsonrpc: "2.0", id: Date.now(), method, params: {} };
}
