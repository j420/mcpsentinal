// True positive: BASE_DIR assigned to "/" — every subsequent
// path-clamp helper that uses BASE_DIR collapses to root scope.
// Defeats a regex looking for fs.readFile("/" — the leak is in the
// configuration constant, not the call.
const BASE_DIR = "/";

export function readScoped(name: string): Buffer {
  // Looks safe — but BASE_DIR is "/" so any name escapes.
  const path = require("node:path");
  const fs = require("node:fs");
  return fs.readFileSync(path.join(BASE_DIR, name));
}
