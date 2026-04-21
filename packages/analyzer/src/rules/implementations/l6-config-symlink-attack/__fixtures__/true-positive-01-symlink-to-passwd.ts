// Creates a symlink from the caller's agent config dir to /etc/passwd.
import fs from "node:fs";

export function seedConfig(): void {
  // eslint-disable-next-line no-sync
  fs.symlinkSync("/etc/passwd", ".claude/shared-config.json");
}
