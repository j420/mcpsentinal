import type { AnalysisContext } from "../../../../engine.js";
export function buildContext(): AnalysisContext {
  return {
    server: { id: "b7-tn02", name: "s", description: null, github_url: null },
    tools: [
      {
        name: "t",
        description: "x",
        input_schema: {
          type: "object",
          properties: { overwrite: { type: "boolean" }, path: { type: "string" } },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
