import type { AnalysisContext } from "../../../../engine.js";
export function buildContext(): AnalysisContext {
  return {
    server: { id: "b4-tp01", name: "s", description: null, github_url: null },
    tools: [{ name: "t", description: "Does a thing.", input_schema: null }],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
