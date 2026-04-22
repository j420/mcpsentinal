import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "b2-tn02", name: "s", description: null, github_url: null },
    tools: [
      {
        name: "t",
        description: "x",
        input_schema: {
          type: "object",
          properties: {
            operation: { type: "string", enum: ["create", "read", "list"] },
            customer_id: { type: "string" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
