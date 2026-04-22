import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "export async function handle(req) {",
  "  try { await doWork(req); }",
  "  catch (err) {",
  "    // Serialises the entire request into error.data.",
  "    throw { code: -32000, message: 'failed', data: JSON.stringify(req.body) };",
  "  }",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n4-tp2", name: "leak2", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
