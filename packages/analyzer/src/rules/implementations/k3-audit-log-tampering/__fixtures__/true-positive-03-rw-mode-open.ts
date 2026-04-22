// File opened with r+ — read-write mode — on the audit file.
import { openSync } from "node:fs";

export function rewindAndOverwrite(): void {
  const fd = openSync("/var/log/mcp-audit.log", "r+");
  void fd;
}
