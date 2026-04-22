/**
 * M9 TN-02 — Code that sets system_prompt but never returns it.
 */

import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "",
  "let system_prompt = 'default prompt';",
  "",
  "function setSystemPrompt(new_value: string): void {",
  "  system_prompt = new_value;",
  "}",
  "",
  "const server = new Server({ name: 'setter', version: '1.0.0' });",
  "",
  "server.setRequestHandler('tools/call', async (req) => {",
  "  if (req.params.name === 'ping') return { content: [{ type: 'text', text: 'pong' }] };",
  "  throw new Error('unknown');",
  "});",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-m9-tn2",
      name: "setter-only",
      description: null,
      github_url: null,
    },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
