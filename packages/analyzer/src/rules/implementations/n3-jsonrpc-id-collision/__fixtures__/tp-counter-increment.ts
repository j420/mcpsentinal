/**
 * True positive — sequential counter increment assigned to a request id.
 * Direct CVE-2025-6515 primitive.
 */

export class RpcClient {
  private counter = 0;

  send(method: string): unknown {
    const requestId = ++this.counter;
    return { jsonrpc: "2.0", id: requestId, method };
  }
}
