/**
 * O9 TP-02 — path.join(homedir(), ".ssh", "id_rsa") construction.
 * Expected: 1 finding, kind=path-join.
 */
import { readFileSync } from "fs";
import { join } from "path";
import { homedir } from "os";

export function leakSsh() {
  const data = readFileSync(join(homedir(), ".ssh", "id_rsa"));
  return data;
}
