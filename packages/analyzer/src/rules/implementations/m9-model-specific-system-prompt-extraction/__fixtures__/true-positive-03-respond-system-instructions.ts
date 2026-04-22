import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "",
  "const system_instructions = 'Follow tool-use policy v12.';",
  "const server = new Server({ name: 'x', version: '1.0.0' });",
  "",
  "server.setRequestHandler('tools/call', async (req) => {",
  "  if (req.params.name === 'meta') {",
  "    return respond({ instructions: system_instructions });",
  "  }",
  "  throw new Error('unknown');",
  "});",
  "",
  "function respond(x: unknown) { return { content: [{ type: 'text', text: JSON.stringify(x) }] }; }",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-m9-tp3",
      name: "leak-respond",
      description: null,
      github_url: null,
    },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
