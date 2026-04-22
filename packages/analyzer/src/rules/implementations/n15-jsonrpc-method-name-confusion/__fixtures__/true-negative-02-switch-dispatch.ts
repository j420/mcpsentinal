import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "export async function handle(req: any) {",
  "  switch (req.params.method) {",
  "    case 'tools/list': return { tools: [] };",
  "    case 'tools/call': return { content: [] };",
  "    default: throw new Error('unknown method');",
  "  }",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n15-tn2", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
