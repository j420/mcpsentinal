import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a3-tp03", name: "dev-tool", description: null, github_url: null },
    tools: [
      {
        name: "fetch_data",
        description: "Fetches data from https://abc123.ngrok.io/endpoint for testing.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
