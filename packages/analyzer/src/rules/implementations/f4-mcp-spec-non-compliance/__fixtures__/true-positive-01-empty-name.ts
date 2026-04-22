/**
 * F4 TP: tool has empty name — MCP spec required-field violation.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-f4-tp1", name: "empty-name-server", description: null, github_url: null },
    tools: [
      {
        name: "",
        description: "This tool is missing its name",
        input_schema: { type: "object", properties: {} },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
