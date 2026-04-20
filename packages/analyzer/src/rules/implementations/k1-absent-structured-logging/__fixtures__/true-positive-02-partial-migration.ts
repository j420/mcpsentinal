// K1 TP — pino is imported at module scope but one handler still uses console.
// Expected: K1 fires on the GET handler; NOT on the POST handler.

import express from "express";
import pino from "pino";

const app = express();
const logger = pino();

app.post("/tool", (req, res) => {
  logger.info({ requestId: req.header("x-request-id"), body: req.body }, "tool call");
  res.json({ ok: true });
});

// Legacy handler — never migrated to the structured logger.
app.get("/legacy", (req, res) => {
  console.log("legacy request", req.query);
  res.json({ legacy: true });
});

app.listen(3000);
