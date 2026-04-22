import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import logger from 'pino'",
  "export async function handle(req: any) {",
  "  // logger.info with user-controlled body string",
  "  logger.info(`processing ${req.params.name}`);",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n9-tp3", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
