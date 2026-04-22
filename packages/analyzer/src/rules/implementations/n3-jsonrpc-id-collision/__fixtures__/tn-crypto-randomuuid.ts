/**
 * True negative — cryptographically random id.
 */

import * as crypto from "node:crypto";

export function buildRequest(method: string): unknown {
  const requestId = crypto.randomUUID();
  return { jsonrpc: "2.0", id: requestId, method };
}
