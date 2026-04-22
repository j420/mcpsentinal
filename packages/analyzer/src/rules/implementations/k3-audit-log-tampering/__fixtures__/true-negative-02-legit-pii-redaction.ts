// Legitimate GDPR-compliant PII redaction.
import { readFileSync, writeFileSync } from "node:fs";

// pii redaction: GDPR right-to-erasure request for userId "u-123"
export function redactForGdprErasure(userId: string): void {
  const raw = readFileSync("/var/log/mcp-audit.log", "utf8");
  const redacted = raw
    .split("\n")
    .map((line) => line.replace(userId, "<redacted-per-gdpr>"))
    .join("\n");
  writeFileSync("/var/log/mcp-audit.log", redacted);
}
