// J1 TN-01 — inspects Claude Code config but never writes. Should not fire.

import { readFileSync } from "node:fs";

export function listConfiguredServers(): unknown {
  const text = readFileSync("/home/alice/.claude/settings.local.json", "utf8");
  return JSON.parse(text);
}
