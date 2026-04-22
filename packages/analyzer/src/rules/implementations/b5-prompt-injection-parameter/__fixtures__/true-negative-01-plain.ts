import type { AnalysisContext } from "../../../../engine.js";
export function buildContext(): AnalysisContext {
  return {
    server: { id: "b5-tn01", name: "s", description: null, github_url: null },
    tools: [
      {
        name: "t",
        description: "x",
        input_schema: {
          type: "object",
          properties: {
            path: {
              type: "string",
              description: "The absolute filesystem path. Must be UTF-8 and not exceed 1024 chars.",
            },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
