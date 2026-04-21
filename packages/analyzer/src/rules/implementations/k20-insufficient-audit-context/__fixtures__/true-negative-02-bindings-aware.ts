/**
 * K20 TN-02 — pino.child({ correlation_id }).info({ user_id, tool,
 * outcome, timestamp }, "...") — bindings-aware. The child() bindings
 * contribute the correlation id; the info() arg contributes the other
 * four. 5 aliases total, adequate.
 */

import pino from "pino";

const logger = pino();

export function handleToolCall(
  correlation_id: string,
  user_id: string,
  tool: string,
  outcome: string,
  timestamp: string,
): void {
  logger.child({ correlation_id }).info({ user_id, tool, outcome, timestamp }, "handled");
}
