import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "export async function handle(req) {",
  "  return new Promise((resolve, reject) => {",
  "    if (!req.query.id) {",
  "      // error.message carries req.query user input verbatim",
  "      reject(new Error(`Missing id. Received: ${req.query.raw}`));",
  "    }",
  "  });",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n4-tp3", name: "leak3", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
