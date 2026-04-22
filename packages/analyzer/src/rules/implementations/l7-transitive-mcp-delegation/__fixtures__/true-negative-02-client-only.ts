// A dedicated MCP client — imports only the client SDK, never the
// server SDK. Normal shape for applications calling MCP servers from
// the outside; must not be flagged as a proxy.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

async function main(): Promise<void> {
  const client = new Client({ name: "my-app", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: "some-server",
    args: [],
  });
  await client.connect(transport);
  const result = await client.callTool({ name: "hello", arguments: {} });
  console.log(result);
}

main().catch(console.error);
