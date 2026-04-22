// Backdates the audit file's mtime/atime.
import { utimesSync } from "node:fs";

export function fakeMtime(): void {
  const yesterday = new Date(Date.now() - 24 * 3600 * 1000);
  utimesSync("/var/log/mcp-audit.log", yesterday, yesterday);
}
