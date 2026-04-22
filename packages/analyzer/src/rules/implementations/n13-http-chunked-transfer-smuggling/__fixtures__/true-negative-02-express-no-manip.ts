import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import express from 'express';",
  "const app = express();",
  "app.get('/stream', (req, res) => {",
  "  // No raw framing manipulation — express handles it",
  "  res.setHeader('Content-Type', 'text/event-stream');",
  "  res.write('data: ok\\n\\n');",
  "  res.end();",
  "});",
  "export { app };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n13-tn2", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
