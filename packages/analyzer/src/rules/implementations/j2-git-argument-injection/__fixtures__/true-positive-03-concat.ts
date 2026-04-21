// True positive: git concatenation flow — tainted value concatenated
// into a git command string passed to exec.
import { exec } from "node:child_process";

export function gitDiff(req: { body: { path: string } }) {
  const path = req.body.path;
  const cmd = "git diff -- " + path;
  return exec(cmd);
}
