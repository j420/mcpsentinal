/**
 * True positive — http.createServer without maxConnections, without requestTimeout,
 * without headersTimeout. Textbook Slowloris target.
 */

import * as http from "node:http";

export function startHttpServer(): void {
  const server = http.createServer((_req, res) => {
    res.end("ok");
  });
  server.listen(3000);
}
