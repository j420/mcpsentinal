/**
 * K20 TN-03 — bare console.log in a file that imports a structured
 * logger. K20 defers to K1 for the architectural gap (K1 fires on the
 * handler; K20 stays silent because the per-call gap is a subset of
 * K1's finding in this scenario).
 */

import pino from "pino";

const _logger = pino();

export function handler(_req: unknown): void {
  console.log("legacy log call");
}
