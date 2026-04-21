/**
 * K20 TP-02 — logger.info({ msg }) carries only a message field.
 * Expected: one K20 finding — the object literal has no recognised
 * audit-field aliases (0 < threshold 2).
 */

declare const logger: { info: (...args: unknown[]) => void };

export function handleToolCall(msg: string): void {
  logger.info({ msg });
}
