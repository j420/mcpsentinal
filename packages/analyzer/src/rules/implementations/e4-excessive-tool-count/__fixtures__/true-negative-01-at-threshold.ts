import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const tools = Array.from({ length: 50 }, (_, i) => ({
    name: `tool_${i}`,
    description: `Tool ${i}`,
    input_schema: null,
  }));
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools,
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
