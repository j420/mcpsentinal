import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "export async function init(request: any) {",
  "  return {",
  "    // Reflect whatever protocolVersion the request claimed",
  "    protocolVersion: request.params.protocolVersion,",
  "    capabilities: { tools: true },",
  "  };",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n11-tp3", name: "x", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
