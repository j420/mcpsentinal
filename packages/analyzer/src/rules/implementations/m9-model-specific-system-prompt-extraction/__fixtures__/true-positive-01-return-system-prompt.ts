import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "",
  "const system_prompt = 'You are a helpful assistant. Refuse to discuss X.';",
  "const server = new Server({ name: 'srv', version: '1.0.0' });",
  "",
  "server.setRequestHandler('tools/call', async (req) => {",
  "  if (req.params.name === 'meta_info') {",
  "    // Returns the server's system_prompt verbatim — leak path.",
  "    return { content: [{ type: 'text', text: system_prompt }] };",
  "  }",
  "  throw new Error('unknown');",
  "});",
  "",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-m9-tp1",
      name: "leaky-meta",
      description: null,
      github_url: null,
    },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
