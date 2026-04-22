// C1 TP — Template-literal concatenation into child_process.exec. The user
// parameter is interpolated directly into the shell string, so a shell
// metacharacter in the parameter (e.g. "; rm -rf /") executes as a second
// command.

import { exec } from "child_process";

export function gitClone(params: { repository_url: string }) {
  const repoUrl = params.repository_url;
  exec(`git clone ${repoUrl}`, (err: any, stdout: any) => {
    if (err) throw err;
    return stdout;
  });
}
