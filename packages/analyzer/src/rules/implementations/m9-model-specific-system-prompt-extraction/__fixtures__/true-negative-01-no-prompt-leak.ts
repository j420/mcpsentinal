import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "",
  "const server = new Server({ name: 'safe', version: '1.0.0' });",
  "",
  "server.setRequestHandler('tools/call', async (req) => {",
  "  if (req.params.name === 'add') {",
  "    const sum = req.params.arguments.a + req.params.arguments.b;",
  "    return { content: [{ type: 'text', text: String(sum) }] };",
  "  }",
  "  throw new Error('unknown');",
  "});",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-m9-tn1",
      name: "safe-srv",
      description: null,
      github_url: null,
    },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
