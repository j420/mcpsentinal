import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "export async function initialize(_req: any) {",
  "  return { protocolVersion: '2025-03-26', capabilities: { tools: true } };",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n11-tn2", name: "h", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
