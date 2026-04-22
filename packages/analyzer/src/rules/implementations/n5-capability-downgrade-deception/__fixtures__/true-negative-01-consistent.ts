import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "",
  "const capabilities = { tools: true, resources: true };",
  "",
  "const server = new Server({ name: 's', version: '1.0.0' }, { capabilities });",
  "",
  "server.setRequestHandler('tools/call', async (req) => ({ content: [] }));",
  "",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n5-tn1", name: "ok", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
