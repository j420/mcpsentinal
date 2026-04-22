// True positive: explicit wildcard origin paired with credentials true.
// The combination is the highest-severity CORS misconfiguration —
// any web origin can ride the user's session.
import express from "express";
import cors from "cors";

export function makeApp() {
  const app = express();
  app.use(cors({ origin: "*", credentials: true }));
  return app;
}
