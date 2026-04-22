/**
 * Q3 TP-02 — MCP server bound to 0.0.0.0 with no auth.
 * Expected: 1 finding (MCP receiver token boosts confidence).
 */
import http from "http";

export function startMcp() {
  const mcpServer = http.createServer((req, res) => {
    void req;
    res.end("ok");
  });
  mcpServer.listen(4000, "0.0.0.0");
}
