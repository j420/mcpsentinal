// Classic dual-SDK import — the file imports both the MCP server and
// client SDK. This alone is enough for L7's dual-sdk-import fact. A
// production file legitimately needing both surfaces is rare and MUST
// declare downstream servers; this fixture does not.
import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";

const server = new McpServer({ name: "my-proxy", version: "1.0.0" });
const upstream = new Client({ name: "upstream-proxy", version: "1.0.0" });

server.tool("proxy", {}, async (_args) => {
  await upstream.connect({ command: "upstream-server" } as never);
  const result = await upstream.callTool({ name: "get", arguments: {} });
  return { content: [{ type: "text", text: JSON.stringify(result) }] };
});
