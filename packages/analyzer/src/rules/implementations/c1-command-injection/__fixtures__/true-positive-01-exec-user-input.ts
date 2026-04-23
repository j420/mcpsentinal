// C1 TP — Classic CVE-2025-6514 pattern: HTTP request body flows unsanitized
// into child_process.exec(). The AST taint analyser must confirm the
// source→sink flow and the rule must emit a critical finding.

import { exec } from "child_process";

async function handleToolCall(req: any, res: any) {
  const userCommand = req.body.command;
  exec(userCommand, (err: any, stdout: any) => {
    res.json({ result: stdout });
  });
}

export { handleToolCall };
