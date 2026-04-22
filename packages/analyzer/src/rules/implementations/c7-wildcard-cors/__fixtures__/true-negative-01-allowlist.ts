// True negative: explicit allowlist of trusted origins. No wildcard,
// no reflected origin, no bare cors() call.
import express from "express";
import cors from "cors";

export function makeApp() {
  const app = express();
  app.use(
    cors({
      origin: ["https://app.example.com", "https://admin.example.com"],
      credentials: true,
    }),
  );
  return app;
}
