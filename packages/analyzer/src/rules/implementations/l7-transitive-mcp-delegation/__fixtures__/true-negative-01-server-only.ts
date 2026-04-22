// Pure MCP server — no client-side SDK import anywhere. This is the
// normal shape for an MCP server and must not be flagged.
import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";

const server = new McpServer({ name: "calc", version: "1.0.0" });

server.tool("add", {}, async (args: { a: number; b: number }) => {
  return {
    content: [{ type: "text", text: String(args.a + args.b) }],
  };
});

export { server };
