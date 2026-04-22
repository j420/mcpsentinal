/**
 * M6 TN-01 — Accumulation pattern with an explicit size limit nearby.
 * Rule should still fire but with present=true mitigation and lower
 * confidence — or skip entirely per the "honest refusal" charter
 * guidance. We assert mitigation present=true and confidence cap.
 */

import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "",
  "const MAX_HISTORY_SIZE = 100;",
  "const history: string[] = [];",
  "",
  "export const server = new Server({ name: 'bounded', version: '1.0.0' });",
  "",
  "server.setRequestHandler('tools/call', async (req) => {",
  "  if (req.params.name === 'store_note') {",
  "    history.push(req.params.arguments.text);",
  "    // Truncate when over the limit",
  "    if (history.length > MAX_HISTORY_SIZE) history.length = MAX_HISTORY_SIZE;",
  "    return { content: [] };",
  "  }",
  "  if (req.params.name === 'clear_notes') {",
  "    history.length = 0;",
  "    return { content: [] };",
  "  }",
  "  throw new Error('unknown');",
  "});",
  "",
  "async function append_with_ttl(v: string): Promise<void> {",
  "  // Entries expire after an hour - a ttl check runs before every read",
  "  history.push(v);",
  "  if (history.length > MAX_HISTORY_SIZE) history.shift();",
  "}",
  "",
  "async function main(): Promise<void> { await server.connect(); }",
  "main().catch((err) => { console.error(err); process.exit(1); });",
  "",
  "function f1(): number { return 1; }",
  "function f2(): number { return 2; }",
  "function f3(): number { return 3; }",
  "function f4(): number { return 4; }",
  "function f5(): number { return 5; }",
  "function f6(): number { return 6; }",
  "function f7(): number { return 7; }",
  "function f8(): number { return 8; }",
  "function f9(): number { return 9; }",
  "function f10(): number { return 10; }",
  "function f11(): number { return 11; }",
  "function f12(): number { return 12; }",
  "function f13(): number { return 13; }",
  "function f14(): number { return 14; }",
  "function f15(): number { return 15; }",
  "function f16(): number { return 16; }",
  "function f17(): number { return 17; }",
  "function f18(): number { return 18; }",
  "function f19(): number { return 19; }",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-m6-tn1",
      name: "bounded",
      description: null,
      github_url: null,
    },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
