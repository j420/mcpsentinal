// True negative: no filesystem access at all. The MCP server only
// computes pure functions and returns the result.
export function add(a: number, b: number): number {
  return a + b;
}
