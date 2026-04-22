/**
 * F4 TN: tool with empty inputSchema properties ({}) is acceptable — empty-parameter tool.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-f4-tn2", name: "zero-param-tool", description: null, github_url: null },
    tools: [
      {
        name: "ping",
        description: "Health-check tool that takes no arguments.",
        input_schema: { type: "object", properties: {} },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
