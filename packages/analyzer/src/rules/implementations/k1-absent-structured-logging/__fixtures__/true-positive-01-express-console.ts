// K1 TP — Express handler uses console.log, no structured logger imported.
// Expected: K1 fires on the POST /tool handler.

import express from "express";

const app = express();

app.post("/tool", (req, res) => {
  console.log("received tool call", req.body);
  res.json({ ok: true });
});

app.listen(3000);
