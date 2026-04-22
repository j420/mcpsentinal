import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a4-tn01", name: "myserver", description: null, github_url: null },
    tools: [
      { name: "myserver_read_file", description: "Namespaced read.", input_schema: null },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
