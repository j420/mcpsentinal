/**
 * M6 TP-02 — Conversation history push with no truncation / clear.
 *
 * The server's conversation buffer grows monotonically. No nearby bound.
 */

import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { Server } from '@modelcontextprotocol/sdk';",
  "",
  "const conversation_history: Array<{ role: string; content: string }> = [];",
  "",
  "export const server = new Server({ name: 'conv', version: '1.0.0' });",
  "",
  "async function readIssue(repo: string, id: number): Promise<string> {",
  "  const url = `https://api.github.com/repos/${repo}/issues/${id}`;",
  "  const r = await fetch(url);",
  "  const j = await r.json();",
  "  return j.body;",
  "}",
  "",
  "server.setRequestHandler('tools/call', async (req) => {",
  "  if (req.params.name === 'fetch_issue') {",
  "    const body = await readIssue(req.params.arguments.repo, req.params.arguments.id);",
  "    // Push the fetched content into the shared conversation buffer. No",
  "    // truncation, no eviction, no TTL — the buffer accumulates forever.",
  "    conversation_history.push({ role: 'tool', content: body });",
  "    return { content: [{ type: 'text', text: body }] };",
  "  }",
  "  if (req.params.name === 'retrieve_recent') {",
  "    return { content: conversation_history.slice(-10) };",
  "  }",
  "  throw new Error('unknown');",
  "});",
  "",
  "async function pushSummary(summary: string): Promise<void> {",
  "  conversation_history.push({ role: 'system', content: summary });",
  "}",
  "",
  "async function pushError(err: string): Promise<void> {",
  "  conversation_history.push({ role: 'system', content: err });",
  "}",
  "",
  "async function pushMetric(n: number): Promise<void> {",
  "  conversation_history.push({ role: 'system', content: `metric=${n}` });",
  "}",
  "",
  "export async function main(): Promise<void> {",
  "  await server.connect();",
  "}",
  "",
  "main().catch((err) => { console.error(err); process.exit(1); });",
  "",
  "function filler1(): number { return 1; }",
  "function filler2(): number { return 2; }",
  "function filler3(): number { return 3; }",
  "function filler4(): number { return 4; }",
  "function filler5(): number { return 5; }",
  "function filler6(): number { return 6; }",
  "function filler7(): number { return 7; }",
  "function filler8(): number { return 8; }",
  "function filler9(): number { return 9; }",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-m6-tp2",
      name: "unbounded-conv",
      description: null,
      github_url: null,
    },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
