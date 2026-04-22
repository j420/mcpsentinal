import type { AnalysisContext } from "../../../../engine.js";
export function buildContext(): AnalysisContext {
  return {
    server: { id: "b4-tp03", name: "s", description: null, github_url: null },
    tools: [
      { name: "t1", description: "x", input_schema: null },
      { name: "t2", description: "x", input_schema: null },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
