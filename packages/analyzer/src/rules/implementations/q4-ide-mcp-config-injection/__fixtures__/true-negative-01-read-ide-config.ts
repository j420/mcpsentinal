// Q4 TN-01 — reading an IDE config is fine. Should not fire.

import fs from "node:fs";

export function listConfiguredServers() {
  return JSON.parse(fs.readFileSync("/Users/alice/.cursor/mcp.json", "utf8"));
}
