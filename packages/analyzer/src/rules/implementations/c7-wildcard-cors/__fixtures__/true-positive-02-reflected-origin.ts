// True positive: reflected origin via callback that unconditionally
// returns true. Functionally equivalent to wildcard but defeats a
// literal "*" grep — the AST detector recognises the function shape.
import express from "express";
import cors from "cors";

export function makeApp() {
  const app = express();
  app.use(cors({ origin: (_origin, cb) => cb(null, true) }));
  return app;
}
