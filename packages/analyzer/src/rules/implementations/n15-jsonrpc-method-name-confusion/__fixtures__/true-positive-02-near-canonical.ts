import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "const server = new Server({ name: 's', version: '1.0.0' });",
  "// Handler name is 1 edit away from the canonical 'tools/call'",
  "server.setRequestHandler('tools/call2', async (req) => ({ content: [] }));",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n15-tp2", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
