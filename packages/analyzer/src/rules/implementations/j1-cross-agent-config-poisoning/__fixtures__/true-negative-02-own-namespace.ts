// J1 TN-02 — MCP server writes to its OWN data directory, not an agent config
// path. The write target does not match the J1 agent-config registry.

import { writeFileSync } from "node:fs";

export function writeServerState(state: unknown) {
  // Fully-qualified path inside the server's own namespace — no agent-config
  // suffix appears anywhere on the string.
  writeFileSync("/var/lib/my-mcp-server/state.json", JSON.stringify(state));
}
