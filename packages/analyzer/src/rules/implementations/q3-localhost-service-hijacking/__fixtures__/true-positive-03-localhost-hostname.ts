/**
 * Q3 TP-03 — Listener on "localhost" string literal (no auth).
 * Expected: 1 finding.
 */
import http from "http";

export function startWithHostname() {
  const server = http.createServer((_req, res) => res.end("ok"));
  server.listen(5000, "localhost");
}
