import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const props: Record<string, Record<string, unknown>> = {};
  for (let i = 0; i < 20; i++) props[`p${i}`] = { type: "string" };
  return {
    server: { id: "b3-tp01", name: "s", description: null, github_url: null },
    tools: [{ name: "t", description: "x", input_schema: { type: "object", properties: props } }],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
