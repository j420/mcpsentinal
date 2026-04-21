/**
 * True negative — nanoid produces unpredictable ids.
 */

declare function nanoid(): string;

export function buildRequest(method: string): unknown {
  const requestId = nanoid();
  return { jsonrpc: "2.0", id: requestId, method };
}
