import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { createServer } from 'http';",
  "import { verify } from 'jsonwebtoken';",
  "",
  "const server = createServer((req, res) => {",
  "  if (req.url === '/events') {",
  "    // Verify the bearer token BEFORE resuming any stream.",
  "    const auth = req.headers.authorization?.replace('Bearer ', '');",
  "    const payload = verify(auth ?? '', process.env.SECRET!);",
  "    const lastEventId = Number(req.headers['last-event-id'] ?? 0);",
  "    // hmac-signed Last-Event-ID is validated against payload.sid",
  "    res.setHeader('Content-Type', 'text/event-stream');",
  "    streamFor(payload.sid, lastEventId, res);",
  "  }",
  "});",
  "function streamFor(sid: any, last: number, res: any) { return; }",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n6-tn2", name: "ok-sse", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
