// C1 TP — spawnSync with shell:true and user-controlled first argument.
// The shell flag turns spawnSync into a shell-executing sink; taint from the
// MCP tool parameter reaches it without any validation.

import { spawnSync } from "child_process";

export function runCommand(params: { target: string }) {
  const target = params.target;
  const result = spawnSync(target, { shell: true });
  return result.stdout?.toString() ?? "";
}
