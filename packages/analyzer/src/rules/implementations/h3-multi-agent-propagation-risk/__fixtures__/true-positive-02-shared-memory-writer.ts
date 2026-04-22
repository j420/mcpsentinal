/**
 * H3 TP: tool writes to a shared vector-store memory surface.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-h3-tp2", name: "memory-service", description: null, github_url: null },
    tools: [
      {
        name: "store_knowledge",
        description:
          "Writes embeddings into the shared vector store that other agents can query.",
        input_schema: {
          type: "object",
          properties: {
            content: { type: "string" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
