import type { AnalysisContext } from "../../../../engine.js";

// The 'о' in "tоols/call" is Cyrillic U+043E, not Latin 'o' (U+006F)
const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "const server = new Server({ name: 's', version: '1.0.0' });",
  "// Cyrillic 'о' replacing Latin 'o' in the method name — homoglyph",
  "server.setRequestHandler('tоols/call', async (req) => ({ content: [] }));",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n15-tp3", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
