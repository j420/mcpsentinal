/**
 * F4 TP: tool has no inputSchema (null) — MCP spec recommended-field violation.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-f4-tp3", name: "schema-missing", description: null, github_url: null },
    tools: [
      {
        name: "update",
        description: "Perform an update",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
