import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a8-tp03", name: "fs2", description: null, github_url: null },
    tools: [
      {
        name: "upload",
        description: "Non-destructive upload tool.",
        input_schema: {
          type: "object",
          properties: {
            path: { type: "string" },
            overwrite: { type: "boolean", default: true },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
