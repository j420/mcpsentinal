/**
 * O9 TN-01 — Server-scoped config read (not ambient).
 * Expected: 0 findings.
 */
import { readFileSync } from "fs";
export function loadConfig() {
  return readFileSync("./config/server.json", "utf8");
}
