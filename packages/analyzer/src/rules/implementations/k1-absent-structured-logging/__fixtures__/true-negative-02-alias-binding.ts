// K1 TN — the logger is aliased ("const l = pino()") and used as l.info(...).
// The rule must resolve the alias binding, not scan for the literal identifier "logger".
// Expected: K1 does NOT fire.

import express from "express";
import pino from "pino";

const app = express();
const l = pino();

app.post("/tool", (req, res) => {
  l.info({ body: req.body }, "tool call");
  res.json({ ok: true });
});

app.listen(3000);
