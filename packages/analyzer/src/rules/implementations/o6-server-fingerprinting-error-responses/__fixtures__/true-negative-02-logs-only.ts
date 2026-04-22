/**
 * O6 TN-02 — Fingerprint surface is READ but only flows into a structured
 * logger (pino), never into a response body or Error payload. The response
 * is a generic success shape.
 * Expected: 0 findings.
 */
import os from "os";
import pino from "pino";

const logger = pino();

export function bootCheck(_req: unknown, res: any) {
  logger.info({ hostname: os.hostname(), version: process.version }, "boot");
  res.json({ ok: true });
}
