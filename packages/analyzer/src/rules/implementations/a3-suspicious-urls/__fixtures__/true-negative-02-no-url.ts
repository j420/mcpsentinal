import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a3-tn02", name: "plain", description: null, github_url: null },
    tools: [
      {
        name: "add",
        description: "Adds two numbers and returns the sum.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
