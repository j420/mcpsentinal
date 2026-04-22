import type { AnalysisContext } from "../../../../engine.js";
export function buildContext(): AnalysisContext {
  return {
    server: { id: "b6-tn01", name: "s", description: null, github_url: null },
    tools: [
      {
        name: "t",
        description: "x",
        input_schema: {
          type: "object",
          properties: { a: { type: "string" } },
          additionalProperties: false,
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
