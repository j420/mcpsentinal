/**
 * Q3 TN-02 — Localhost bind with explicit bearer-token check in scope.
 * Expected: 0 findings (auth suppression).
 */
import http from "http";

export function startAuthenticated() {
  const bearer = process.env.AUTH_TOKEN;
  const server = http.createServer((req, res) => {
    const authorization = req.headers["authorization"];
    if (authorization !== `Bearer ${bearer}`) {
      res.writeHead(401);
      res.end();
      return;
    }
    res.end("ok");
  });
  server.listen(3000, "127.0.0.1");
}
