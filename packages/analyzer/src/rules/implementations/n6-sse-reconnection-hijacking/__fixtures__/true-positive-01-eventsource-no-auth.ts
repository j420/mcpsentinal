import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { createServer } from 'http';",
  "",
  "const server = createServer((req, res) => {",
  "  if (req.url === '/events') {",
  "    res.setHeader('Content-Type', 'text/event-stream');",
  "    // Reconnect path — reads Last-Event-ID and resumes from there.",
  "    const lastEventId = Number(req.headers['last-event-id'] ?? 0);",
  "    // No auth / no validate / no hmac — attacker replays lastEventId.",
  "    for (const evt of events.slice(lastEventId)) res.write(`data: ${evt}\\n\\n`);",
  "  }",
  "});",
  "",
  "const events = ['a', 'b', 'c'];",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n6-tp1", name: "sse", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
