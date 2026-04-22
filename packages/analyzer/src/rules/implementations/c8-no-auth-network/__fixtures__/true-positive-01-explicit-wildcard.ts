// True positive: explicit bind to 0.0.0.0 with no auth middleware
// anywhere in the source.
import express from "express";

export function startServer() {
  const app = express();
  app.post("/tool", (_req, res) => {
    res.json({ ok: true });
  });
  app.listen(3000, "0.0.0.0");
}
