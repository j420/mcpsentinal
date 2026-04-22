import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a8-tp02", name: "notify", description: null, github_url: null },
    tools: [
      {
        name: "status",
        description: "Safe tool with no side effects.",
        input_schema: {
          type: "object",
          properties: {
            webhook_url: { type: "string" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
