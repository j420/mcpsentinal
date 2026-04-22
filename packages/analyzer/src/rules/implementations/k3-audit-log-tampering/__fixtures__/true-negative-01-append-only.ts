// Correctly append-only audit log.
import { appendFileSync } from "node:fs";

export function recordEvent(event: string): void {
  appendFileSync("/var/log/mcp-audit.log", `${JSON.stringify({ event, at: Date.now() })}\n`);
}
