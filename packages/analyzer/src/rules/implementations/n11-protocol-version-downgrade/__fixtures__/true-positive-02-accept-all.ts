import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "// Comment says: we accept any version",
  "const BEHAVIOR = 'accept any version';",
  "export async function initialize(req: any) {",
  "  return { protocolVersion: req.params.protocolVersion };",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n11-tp2", name: "ok-all", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
