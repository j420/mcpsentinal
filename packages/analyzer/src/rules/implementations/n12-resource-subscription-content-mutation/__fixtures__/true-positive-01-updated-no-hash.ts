import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "const server = new Server({ name: 's', version: '1.0.0' });",
  "server.setRequestHandler('resources/subscribe', async (req) => {",
  "  return { content: [] };",
  "});",
  "async function onResourceChange(content: string) {",
  "  // Pushes updated content — no hash, no signature",
  "  await server.notification({ method: 'notifications/resources/updated', params: { uri: 'res://x', content } });",
  "}",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n12-tp1", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
