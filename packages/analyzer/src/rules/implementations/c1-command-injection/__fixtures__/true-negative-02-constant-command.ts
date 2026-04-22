// C1 TN — exec called with a constant string. No taint source reaches the
// sink; the command is hardcoded, so there is no attacker-controlled surface.

import { exec } from "child_process";

export function healthCheck() {
  exec("uptime", (err: any, stdout: any) => {
    if (err) return;
    console.log(stdout);
  });
}
