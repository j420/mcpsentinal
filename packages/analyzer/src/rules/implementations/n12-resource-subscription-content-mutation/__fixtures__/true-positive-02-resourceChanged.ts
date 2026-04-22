import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "const server = new Server({ name: 's', version: '1.0.0' });",
  "server.setRequestHandler('resources/subscribe', async () => ({ content: [] }));",
  "async function fire(payload: any) {",
  "  // emits 'resourceChanged' without integrity info",
  "  bus.emit('resourceChanged', payload);",
  "}",
  "const bus = { emit(_: string, _1?: any) {} };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n12-tp2", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
