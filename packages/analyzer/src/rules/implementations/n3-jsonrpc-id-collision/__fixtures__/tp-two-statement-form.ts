/**
 * True positive — two-statement form (lethal edge case
 * `post-increment-in-template-literal`). A regex looking for `id++` misses
 * this but the sequence produced is identical.
 */

export class PythonStyleClient {
  private _request_id = 0;

  send(method: string): { jsonrpc: string; id: number; method: string } {
    this._request_id += 1;
    const requestId = this._request_id;
    return { jsonrpc: "2.0", id: requestId, method };
  }
}
