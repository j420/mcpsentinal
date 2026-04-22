/**
 * F4 TP: tool has no description — MCP spec recommended-field violation.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-f4-tp2", name: "desc-missing", description: null, github_url: null },
    tools: [
      {
        name: "mystery",
        description: null,
        input_schema: { type: "object", properties: { target: { type: "string" } } },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
