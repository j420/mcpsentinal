import type { AnalysisContext } from "../../../../engine.js";
export function buildContext(): AnalysisContext {
  // Null schema is B4's domain, not B6's.
  return {
    server: { id: "b6-tn02", name: "s", description: null, github_url: null },
    tools: [{ name: "t", description: "x", input_schema: null }],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
