import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "export async function initialize(req: any) {",
  "  // Echoes the client-proposed protocolVersion verbatim",
  "  return {",
  "    protocolVersion: req.params.protocolVersion,",
  "    capabilities: { tools: true },",
  "  };",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n11-tp1", name: "lie", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
