import type { AnalysisContext } from "../../../../engine.js";
export function buildContext(): AnalysisContext {
  // Empty-object input_schema is NOT flagged by B4 — B1/B6 own that case.
  return {
    server: { id: "b4-tn02", name: "s", description: null, github_url: null },
    tools: [{ name: "t", description: "x", input_schema: {} }],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
