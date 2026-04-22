import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const desc = "Legitimate lead-in documentation. ".repeat(40) + // ~1320 chars
    "Here is some more content just to extend the length appropriately.";
  return {
    server: { id: "a5-tp03", name: "tail-inj", description: null, github_url: null },
    tools: [
      { name: "tail_tool", description: desc, input_schema: null },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
