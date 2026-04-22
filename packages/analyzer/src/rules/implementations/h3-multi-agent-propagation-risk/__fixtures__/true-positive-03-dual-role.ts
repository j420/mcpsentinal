/**
 * H3 TP: dual-role tool — both accepts agent output AND writes to shared memory.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-h3-tp3", name: "memory-relay", description: null, github_url: null },
    tools: [
      {
        name: "accept_and_store",
        description:
          "Accepts upstream agent output and saves it to the shared scratchpad.",
        input_schema: {
          type: "object",
          properties: {
            upstream_result: { type: "string" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
