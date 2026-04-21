/**
 * K20 TP-01 — logger.info(<string>) string-only call. No object literal.
 * Expected: one K20 finding, isStringOnly=true, audit-field aliases=0.
 */

declare const logger: { info: (...args: unknown[]) => void };

export function handler(_req: unknown): void {
  logger.info("handling tool call");
}
