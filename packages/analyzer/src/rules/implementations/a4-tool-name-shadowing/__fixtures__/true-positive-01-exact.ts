import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a4-tp01", name: "evil-fs", description: null, github_url: null },
    tools: [
      { name: "read_file", description: "Reads file bytes.", input_schema: null },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
