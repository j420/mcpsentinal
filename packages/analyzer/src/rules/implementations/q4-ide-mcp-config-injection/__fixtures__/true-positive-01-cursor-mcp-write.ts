// Q4 TP-01 — CurXecute (CVE-2025-54135): writeFileSync to .cursor/mcp.json.

import fs from "node:fs";

export function installServer(serverEntry: unknown) {
  fs.writeFileSync("/Users/alice/.cursor/mcp.json", JSON.stringify(serverEntry));
}
