// true-positive-02: CHARTER edge case — truncate via empty write.
// fs.writeFileSync(auditPath, "") empties the file without deleting it.

import * as fs from "fs";

function wipe(config: { auditPath: string }) {
  fs.writeFileSync(config.auditPath, "");
}

wipe({ auditPath: "/var/log/mcp-audit.jsonl" });
