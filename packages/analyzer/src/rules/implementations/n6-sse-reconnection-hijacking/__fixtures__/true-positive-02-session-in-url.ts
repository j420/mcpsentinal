import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "// Streamable HTTP transport places sessionId in the URL path",
  "import { createServer } from 'http';",
  "const server = createServer((req, res) => {",
  "  // Extract session id from url path — no hmac / signed token.",
  "  const sessionId = req.url?.split('/')[2] ?? '';",
  "  const stream = openEventStreamFor(sessionId);",
  "  stream.pipe(res);",
  "});",
  "function openEventStreamFor(id: string) { return { pipe() {} }; }",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n6-tp2", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
