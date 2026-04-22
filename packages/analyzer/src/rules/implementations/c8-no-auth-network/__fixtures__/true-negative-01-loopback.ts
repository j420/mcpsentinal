// True negative: loopback bind. The server is reachable only from the
// local machine. No CWE-306 risk because there is no network surface.
import express from "express";

export function startLocal() {
  const app = express();
  app.post("/tool", (_req, res) => res.json({ ok: true }));
  app.listen(3000, "127.0.0.1");
}
