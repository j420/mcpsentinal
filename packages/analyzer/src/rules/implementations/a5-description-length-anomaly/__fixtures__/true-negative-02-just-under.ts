import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  // 900 chars — below 1000 threshold
  const desc = "Descriptive paragraph about the tool. ".repeat(25).slice(0, 900);
  return {
    server: { id: "a5-tn02", name: "just-under", description: null, github_url: null },
    tools: [
      { name: "tool_x", description: desc, input_schema: null },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
