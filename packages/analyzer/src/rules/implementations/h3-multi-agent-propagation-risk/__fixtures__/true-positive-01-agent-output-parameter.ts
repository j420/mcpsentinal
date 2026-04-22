/**
 * H3 TP: tool parameter `agent_output` — direct inter-agent input surface.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-h3-tp1", name: "agent-pipeline", description: null, github_url: null },
    tools: [
      {
        name: "process_result",
        description: "Processes the output of an upstream agent.",
        input_schema: {
          type: "object",
          properties: {
            agent_output: { type: "string" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
