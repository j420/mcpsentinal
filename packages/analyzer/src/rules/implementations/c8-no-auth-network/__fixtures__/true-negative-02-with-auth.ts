// True negative: bind to 0.0.0.0 BUT a JWT auth middleware is wired
// before any route. The detector recognises the use(authMiddleware)
// call and suppresses the finding.
import express from "express";
import { verifyJwt } from "./auth.js";

export function startServer() {
  const app = express();
  app.use(verifyJwt);
  app.post("/tool", (_req, res) => {
    res.json({ ok: true });
  });
  app.listen(3000, "0.0.0.0");
}
