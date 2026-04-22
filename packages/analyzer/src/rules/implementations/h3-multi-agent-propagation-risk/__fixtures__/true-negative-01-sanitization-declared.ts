/**
 * H3 TN: tool accepts upstream agent output but declares sanitization in its description.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-h3-tn1", name: "safe-relay", description: null, github_url: null },
    tools: [
      {
        name: "relay_validated",
        description:
          "Validates upstream agent output against a strict trust boundary before " +
          "dispatching it downstream. Rejects any content that fails sanitization.",
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
