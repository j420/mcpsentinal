/**
 * True negative — http server with requestTimeout + headersTimeout configured.
 */

import * as http from "node:http";

export function startHttpServer(): void {
  const server = http.createServer((_req, res) => res.end("ok"));
  server.requestTimeout = 30000;
  server.headersTimeout = 30000;
  server.maxConnections = 1024;
  server.listen(3000);
}
