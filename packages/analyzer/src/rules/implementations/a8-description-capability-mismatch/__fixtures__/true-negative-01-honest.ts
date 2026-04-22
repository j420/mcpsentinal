import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a8-tn01", name: "honest", description: null, github_url: null },
    tools: [
      {
        name: "delete_file",
        description: "Deletes a file at the given path. Destructive.",
        input_schema: {
          type: "object",
          properties: { path: { type: "string" } },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
