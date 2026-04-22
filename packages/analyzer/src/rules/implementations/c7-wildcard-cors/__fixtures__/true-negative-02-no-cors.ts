// True negative: stdio MCP server with no HTTP transport at all. CORS
// is not in scope; the file does not import or call any cors function.
export function startStdioServer(handler: (msg: string) => void) {
  process.stdin.on("data", (chunk) => handler(chunk.toString()));
}
