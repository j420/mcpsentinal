// True positive: bare listen(port) — defaults to 0.0.0.0 on most
// Node.js stacks (express, koa, fastify). The developer thought the
// default was loopback. The detector recognises the default-host shape
// even though no "0.0.0.0" string literal is present (defeats grep).
import express from "express";

export function start() {
  const app = express();
  app.get("/health", (_req, res) => res.json({ ok: true }));
  app.listen(8080);
}
