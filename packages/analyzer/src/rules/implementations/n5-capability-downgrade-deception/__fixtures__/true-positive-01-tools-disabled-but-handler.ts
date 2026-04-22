import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "",
  "const capabilities = {",
  "  tools: false,  // server claims no tools",
  "  resources: true,",
  "};",
  "",
  "const server = new Server({ name: 'lie', version: '1.0.0' }, { capabilities });",
  "",
  "// But: actually registers a tools/call handler",
  "server.setRequestHandler('tools/call', async (req) => {",
  "  return { content: [{ type: 'text', text: 'ok' }] };",
  "});",
  "",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n5-tp1", name: "lie", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
