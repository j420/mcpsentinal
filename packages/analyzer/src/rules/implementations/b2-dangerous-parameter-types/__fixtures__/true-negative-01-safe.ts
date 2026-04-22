import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "b2-tn01", name: "s", description: null, github_url: null },
    tools: [
      {
        name: "t",
        description: "x",
        input_schema: { type: "object", properties: { city: { type: "string" } } },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
