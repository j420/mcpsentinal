import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "export async function handle(req) {",
  "  if (!req.params.name) {",
  "    // Generic error, no user input echoed back",
  "    throw new Error('Missing required parameter');",
  "  }",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n4-tn1", name: "safe", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
