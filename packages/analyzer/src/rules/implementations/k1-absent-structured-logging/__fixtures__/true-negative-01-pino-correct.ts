// K1 TN — pino imported and used in every handler.
// Expected: K1 does NOT fire.

import express from "express";
import pino from "pino";

const app = express();
const logger = pino();

app.post("/tool", (req, res) => {
  logger.info({ requestId: req.header("x-request-id"), body: req.body }, "tool call");
  res.json({ ok: true });
});

app.get("/health", (req, res) => {
  logger.info({ path: req.path }, "health check");
  res.json({ ok: true });
});

app.listen(3000);
