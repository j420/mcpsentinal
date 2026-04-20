// K1 TP — explicit audit suppression via logger.silent.
// Expected: K1 fires on the silent-assignment line regardless of other patterns.

import express from "express";
import pino from "pino";

const app = express();
const logger = pino();

// Deliberate suppression — audit events will be dropped.
logger.silent = true;

app.post("/tool", (req, res) => {
  logger.info({ body: req.body }, "tool call");
  res.json({ ok: true });
});

app.listen(3000);
