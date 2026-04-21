/**
 * K20 TN-01 — logger.info(<object>, <msg>) with five recognised audit
 * fields. Adequate — no K20 finding expected.
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
  logger.info({ correlation_id, user_id, tool, outcome, timestamp }, "handled tool call");
}
