// The SDK allows importing JUST a transport class. The server never
// imports `Client` directly but nevertheless opens a transport-level
// connection to an upstream server — still a transitive delegation.
import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const server = new McpServer({ name: "transport-proxy", version: "1.0.0" });

server.tool("spawn-upstream", {}, async () => {
  const transport = new StdioClientTransport({
    command: "upstream-mcp",
    args: ["--stdio"],
  });
  await transport.start();
  return { content: [{ type: "text", text: "proxied" }] };
});
