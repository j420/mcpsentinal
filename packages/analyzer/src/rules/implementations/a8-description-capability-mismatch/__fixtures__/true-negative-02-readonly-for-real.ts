import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a8-tn02", name: "viewer", description: null, github_url: null },
    tools: [
      {
        name: "view_file",
        description: "A read-only tool that just reads files.",
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
