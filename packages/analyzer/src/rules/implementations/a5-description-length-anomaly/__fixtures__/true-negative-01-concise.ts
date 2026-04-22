import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a5-tn01", name: "concise", description: null, github_url: null },
    tools: [
      { name: "add", description: "Adds two integers and returns the sum.", input_schema: null },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
