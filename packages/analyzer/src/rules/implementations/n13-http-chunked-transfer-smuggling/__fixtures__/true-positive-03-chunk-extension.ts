import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import { createServer } from 'http';",
  "const server = createServer((req, res) => {",
  "  // Chunk-extension abuse: writes extensions that intermediaries may misparse",
  "  const header = `5;chunk-extension=foo\\r\\nHELLO\\r\\n0\\r\\n\\r\\n`;",
  "  res.setHeader('Transfer-Encoding', 'chunked');",
  "  res.end(header);",
  "});",
  "export { server };",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n13-tp3", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
