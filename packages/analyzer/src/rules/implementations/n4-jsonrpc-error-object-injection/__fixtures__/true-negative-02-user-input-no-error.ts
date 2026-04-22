import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "// Uses req.params but never flows into an error surface",
  "export async function handle(req) {",
  "  const id = req.params.id;",
  "  const r = await db.find(id);",
  "  return { content: [{ type: 'text', text: r.name }] };",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n4-tn2", name: "safe2", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
