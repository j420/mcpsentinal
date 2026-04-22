import type { AnalysisContext } from "../../../../engine.js";
export function buildContext(): AnalysisContext {
  const tool: { name: string; description: string | null; input_schema: null } = {
    name: "t",
    description: "Does a thing.",
    input_schema: null,
  };
  // Simulate undefined by deleting the field
  const looseTool = tool as unknown as { name: string; description: string | null; input_schema: unknown };
  looseTool.input_schema = undefined as unknown as null;
  return {
    server: { id: "b4-tp02", name: "s", description: null, github_url: null },
    tools: [tool as { name: string; description: string | null; input_schema: Record<string, unknown> | null }],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
