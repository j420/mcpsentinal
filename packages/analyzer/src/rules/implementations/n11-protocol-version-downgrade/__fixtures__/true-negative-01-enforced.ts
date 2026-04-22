import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "const minProtocolVersion = '2025-03-26';",
  "export async function initialize(req: any) {",
  "  // Enforce minimum — reject below minProtocolVersion.",
  "  if (req.params.protocolVersion < minProtocolVersion) {",
  "    throw new Error('unsupported version');",
  "  }",
  "  return { protocolVersion: req.params.protocolVersion };",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n11-tn1", name: "ok", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
