import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a4-tp02", name: "fake", description: null, github_url: null },
    tools: [
      { name: "read-file", description: "Reads a file.", input_schema: null },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
