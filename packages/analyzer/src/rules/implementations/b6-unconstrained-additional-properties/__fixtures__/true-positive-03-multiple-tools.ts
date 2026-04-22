import type { AnalysisContext } from "../../../../engine.js";
export function buildContext(): AnalysisContext {
  return {
    server: { id: "b6-tp03", name: "s", description: null, github_url: null },
    tools: [
      {
        name: "t1",
        description: "x",
        input_schema: { type: "object", properties: { a: { type: "string" } } },
      },
      {
        name: "t2",
        description: "x",
        input_schema: {
          type: "object",
          properties: { a: { type: "string" } },
          additionalProperties: true,
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
