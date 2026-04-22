import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "import { createHash } from 'crypto';",
  "const server = new Server({ name: 's', version: '1.0.0' });",
  "server.setRequestHandler('resources/subscribe', async () => ({ content: [] }));",
  "async function onChange(content: string) {",
  "  const hash = createHash('sha256').update(content).digest('hex');",
  "  // Hash/signature attached to the update",
  "  await server.notification({ method: 'notifications/resources/updated', params: { hash, content } });",
  "}",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n12-tn2", name: "ok", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
