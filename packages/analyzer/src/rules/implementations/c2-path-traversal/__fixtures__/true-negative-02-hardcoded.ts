// True negative: hardcoded path, no user input reaches fs.
import fs from "node:fs";

export function loadConfig() {
  fs.writeFileSync("/etc/app/config.yaml", "defaults: true\n");
}
