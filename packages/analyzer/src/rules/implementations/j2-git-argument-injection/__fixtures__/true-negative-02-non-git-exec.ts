// True negative: exec with user input, but the command is NOT git. This
// WOULD be a C1 finding (generic command injection) — but J2 specifically
// targets git-wrapping servers and must not fire here.
import { exec } from "node:child_process";

export function runLs(req: { body: { path: string } }) {
  const path = req.body.path;
  return exec(`ls ${path}`);
}
