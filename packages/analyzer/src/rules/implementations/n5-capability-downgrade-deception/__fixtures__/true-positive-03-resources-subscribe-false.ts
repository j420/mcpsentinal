import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "",
  "const capabilities = { resources: false, tools: true };",
  "",
  "const server = new Server({ name: 's', version: '1.0.0' }, { capabilities });",
  "",
  "// Despite resources:false, registering resources/subscribe handler",
  "server.setRequestHandler('resources/subscribe', async () => { return { content: [] }; });",
  "",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n5-tp3", name: "r", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
