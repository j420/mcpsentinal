import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { createServer } from 'http';",
  "",
  "// Streamable HTTP transport",
  "const server = createServer((req, res) => {",
  "  // Anti-pattern: both Transfer-Encoding chunked AND Content-Length",
  "  res.setHeader('Transfer-Encoding', 'chunked');",
  "  res.setHeader('Content-Length', '42');",
  "  res.write('data');",
  "  res.end();",
  "});",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n13-tp1", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
