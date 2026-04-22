import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "// trust-on-first-use binding on MCP server",
  "export function bootstrap(identity: string) {",
  "  // accept first identity without operator confirmation",
  "  return { accept_first_identity: identity };",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n14-tp2", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
