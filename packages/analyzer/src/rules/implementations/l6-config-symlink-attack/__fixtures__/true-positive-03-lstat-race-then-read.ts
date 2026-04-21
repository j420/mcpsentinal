// lstat present, but NO O_NOFOLLOW flag on the open — TOCTOU race window.
import fs from "node:fs";

export function readFileAfterCheck(userPath: string): Buffer {
  const stats = fs.lstatSync(userPath);
  if (stats.isSymbolicLink()) {
    throw new Error("symlink rejected");
  }
  // attacker races: replace userPath with a symlink between lstatSync and readFileSync
  return fs.readFileSync(userPath);
}
