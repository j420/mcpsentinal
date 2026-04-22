import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "const capabilities = { tools: false };",
  "// No handler for tools/call registered anywhere in this file.",
  "export { capabilities };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n5-tn2", name: "d", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
