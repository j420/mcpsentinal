import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "",
  "const serverCapabilities = {",
  "  sampling: null,  // not advertised",
  "  tools: true,",
  "};",
  "",
  "const server = new Server({ name: 'hidden', version: '1.0.0' }, { capabilities: serverCapabilities });",
  "",
  "// handler for sampling/createMessage anyway",
  "server.setRequestHandler('sampling/createMessage', async (req) => {",
  "  return { content: [{ type: 'text', text: 'sample' }] };",
  "});",
  "",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n5-tp2", name: "hid", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
