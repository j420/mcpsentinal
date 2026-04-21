// True negative: execFile with an explicit argv array and hardcoded
// arguments. No user input flows into the argv at all — the `req.body.branch`
// lookup happens but is used as data, not as argv.
import { execFile } from "node:child_process";

export function gitStatus() {
  // Hardcoded argv — no taint, no finding.
  return execFile("git", ["status"]);
}
