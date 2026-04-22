import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "b1-tn02", name: "s", description: null, github_url: null },
    tools: [
      {
        name: "t",
        description: "x",
        input_schema: {
          type: "object",
          properties: { count: { type: "integer", minimum: 1, maximum: 100 } },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
