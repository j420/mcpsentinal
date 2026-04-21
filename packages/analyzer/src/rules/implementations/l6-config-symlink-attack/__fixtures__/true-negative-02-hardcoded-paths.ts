// All fs.readFile calls use hard-coded literal paths — no user influence.
import fs from "node:fs";

export function loadConstants(): string {
  return fs.readFileSync("/etc/hostname", "utf8");
}
