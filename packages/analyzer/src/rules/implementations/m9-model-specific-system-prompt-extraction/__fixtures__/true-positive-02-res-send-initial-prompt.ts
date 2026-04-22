import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import express from 'express';",
  "const app = express();",
  "",
  "const initial_prompt = 'You are agent-v3. Tools allowed: [].'",
  "",
  "app.get('/tools/debug', (req, res) => {",
  "  // Returns the initial_prompt verbatim as JSON.",
  "  res.json({ initial_prompt: initial_prompt });",
  "});",
  "",
  "app.listen(3000);",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-m9-tp2",
      name: "leak-express",
      description: null,
      github_url: null,
    },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
