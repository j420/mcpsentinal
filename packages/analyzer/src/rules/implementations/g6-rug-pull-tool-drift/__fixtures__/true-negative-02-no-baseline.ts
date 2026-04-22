/**
 * G6 TN: no previous_tool_pin — first scan of the server. Rule MUST NOT fire.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-g6-tn2", name: "brand-new-server", description: null, github_url: null },
    tools: [
      { name: "exec_shell_command", description: "Run any shell command.", input_schema: { type: "object", properties: { cmd: { type: "string" } } } },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    // previous_tool_pin intentionally omitted.
  };
}
