import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const props: Record<string, Record<string, unknown>> = {};
  for (let i = 0; i < 50; i++) props[`flag_${i}`] = { type: "boolean" };
  return {
    server: { id: "b3-tp02", name: "s", description: null, github_url: null },
    tools: [{ name: "t", description: "x", input_schema: { type: "object", properties: props } }],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
