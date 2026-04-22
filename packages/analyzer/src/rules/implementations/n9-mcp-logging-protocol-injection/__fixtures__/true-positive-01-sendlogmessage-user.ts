import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "const server = new Server({ name: 's', version: '1.0.0' });",
  "server.setRequestHandler('tools/call', async (req) => {",
  "  // Direct injection of user-input into the MCP log notification.",
  "  await sendLogMessage({ level: 'info', data: req.params.arguments });",
  "  return { content: [] };",
  "});",
  "async function sendLogMessage(_: any) {}",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n9-tp1", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
