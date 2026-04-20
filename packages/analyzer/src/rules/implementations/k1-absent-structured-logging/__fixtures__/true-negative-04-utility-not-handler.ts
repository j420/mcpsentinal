// K1 TN — console.log inside a utility function that is NOT a registered handler.
// Expected: K1 does NOT fire — the rule's scope is handlers, not utilities.

import express from "express";
import pino from "pino";

const app = express();
const logger = pino();

function formatDate(d: Date): string {
  console.log("formatDate called"); // utility debug — not a compliance gap
  return d.toISOString();
}

app.post("/tool", (req, res) => {
  logger.info({ body: req.body, ts: formatDate(new Date()) }, "tool call");
  res.json({ ok: true });
});

app.listen(3000);
