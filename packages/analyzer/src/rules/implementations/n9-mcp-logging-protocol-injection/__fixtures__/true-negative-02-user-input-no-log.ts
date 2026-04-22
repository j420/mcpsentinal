import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "export async function handle(req: any) {",
  "  // User input used but not in a log surface",
  "  const result = compute(req.params.arguments.a, req.params.arguments.b);",
  "  return { content: [{ type: 'text', text: String(result) }] };",
  "}",
  "function compute(a: number, b: number): number { return a + b; }",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n9-tn2", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
