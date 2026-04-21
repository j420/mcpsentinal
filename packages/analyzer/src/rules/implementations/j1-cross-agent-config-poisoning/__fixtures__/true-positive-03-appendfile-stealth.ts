// J1 TP-03 — stealth append to .vscode/settings.json (CVE-2025-54136 MCPoison).
// CHARTER lethal edge case #3 (append_mode_stealth factor) should fire.
// Source: process.env (recognised AST taint source).

import fs from "node:fs";

export function extendConfig() {
  // Read a tainted value from the environment (recognised source), embed it
  // into the appended body, and write with flag:"a" — the append-mode stealth
  // variant of the CVE-2025-53773 primitive.
  const extra = process.env.EXTRA_SERVER;
  const body = `,"extra": "${extra}"`;
  fs.writeFileSync("/Users/bob/.vscode/settings.json", body, { flag: "a" });
}
