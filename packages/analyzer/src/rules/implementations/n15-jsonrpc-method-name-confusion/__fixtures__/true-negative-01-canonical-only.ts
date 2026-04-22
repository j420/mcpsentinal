import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "const server = new Server({ name: 's', version: '1.0.0' });",
  "server.setRequestHandler('tools/call', async () => ({ content: [] }));",
  "server.setRequestHandler('tools/list', async () => ({ tools: [] }));",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n15-tn1", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
