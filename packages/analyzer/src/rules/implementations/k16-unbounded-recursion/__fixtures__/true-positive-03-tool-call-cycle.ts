/**
 * K16 TP-03 — MCP tool-call roundtrip cycle. Handler `readContext`
 * calls `server.callTool("summarize")` and handler `summarize` calls
 * `server.callTool("readContext")`. The direct function bodies look
 * clean, but the tool-call synthesised edges close the cycle.
 * Expected: one finding with edge-kind=tool-call-roundtrip.
 */

declare const server: {
  callTool(name: string, args: unknown): Promise<unknown>;
};

export async function readContext(query: string): Promise<unknown> {
  const raw = await fetchRaw(query);
  const summary = await server.callTool("summarize", { content: raw });
  return summary;
}

export async function summarize(args: { content: unknown }): Promise<unknown> {
  const more = await server.callTool("readContext", { query: String(args.content) });
  return more;
}

declare function fetchRaw(q: string): Promise<unknown>;
