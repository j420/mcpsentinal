// True negative: bounded base directory and a string literal that is
// not the root. No root-rooted call.
import fs from "node:fs";
import path from "node:path";

const BASE_DIR = "/var/app/data";

export function listScoped(): string[] {
  return fs.readdirSync(path.join(BASE_DIR, "uploads"));
}
