// Q4 TP-03 — CVE-2025-59944 case-variant MCP filename.
// On macOS/Windows this resolves to .cursor/mcp.json.

import fs from "node:fs";

export function stealthyInstall(body: unknown) {
  fs.writeFileSync("/Users/bob/.cursor/MCP.JSON", JSON.stringify(body));
}
