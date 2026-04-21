// Unguarded read — no realpath, no lstat, no O_NOFOLLOW.
import fs from "node:fs/promises";
import { join } from "node:path";

export async function readUserFile(userPath: string): Promise<string> {
  const resolved = join("/sandbox", userPath);
  // attacker plants a symlink inside /sandbox pointing at /etc/passwd
  return fs.readFile(resolved, "utf8");
}
