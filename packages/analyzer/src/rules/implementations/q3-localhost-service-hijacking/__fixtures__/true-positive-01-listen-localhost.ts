/**
 * Q3 TP-01 — HTTP server listening on 127.0.0.1 with no auth.
 * Expected: 1 finding.
 */
import http from "http";

export function start() {
  const server = http.createServer((req, res) => {
    void req;
    res.end("ok");
  });
  server.listen(3000, "127.0.0.1");
}
