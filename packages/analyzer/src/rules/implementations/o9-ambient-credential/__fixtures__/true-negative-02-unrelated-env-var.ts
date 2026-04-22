/**
 * O9 TN-02 — Reading a file at a path held in an unrelated env var.
 * Expected: 0 findings — the env var is not in AMBIENT_PATH_ENV_VARS.
 */
import { readFileSync } from "fs";
export function loadCustom() {
  return readFileSync(process.env.MY_SERVER_CONFIG_PATH as string, "utf8");
}
