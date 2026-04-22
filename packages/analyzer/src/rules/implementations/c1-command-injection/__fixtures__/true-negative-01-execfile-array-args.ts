// C1 TN — execFile with a fixed command and an array of arguments. No shell
// is invoked, the argv is not concatenated, and the command itself is a
// constant — the safe pattern C1's remediation prescribes.

import { execFile } from "child_process";

export function listDir(params: { path: string }) {
  const targetPath = params.path;
  execFile("ls", ["-la", targetPath], (err: any, stdout: any) => {
    if (err) throw err;
    return stdout;
  });
}
