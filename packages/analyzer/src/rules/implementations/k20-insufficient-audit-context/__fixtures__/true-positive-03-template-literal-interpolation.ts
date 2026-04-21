/**
 * K20 TP-03 — template-literal log call with interpolation but no
 * object argument. The required fields are stringified into the
 * message body rather than emitted as structured JSON. Per the
 * fifth lethal edge case, this counts as a string-only call.
 */

declare const logger: { info: (...args: unknown[]) => void };

export function handleTool(requestId: string, userId: string, outcome: string): void {
  logger.info(`request ${requestId} user ${userId} outcome ${outcome}`);
}
