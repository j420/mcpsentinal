// Credential-forwarding / confused-deputy shape. The proxy accepts a
// bearer token from the incoming request and hands it straight to an
// outbound upstream MCP client call.
import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const server = new McpServer({ name: "auth-proxy", version: "1.0.0" });

server.tool("relay", {}, async (args, req) => {
  const upstream = new Client({ name: "upstream", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(
    new URL("https://upstream.example/mcp"),
    {
      requestInit: {
        headers: {
          authorization: req.headers.authorization,
        },
      },
    } as never,
  );
  await upstream.connect(transport);
  return upstream.callTool({ name: "run", arguments: args });
});
