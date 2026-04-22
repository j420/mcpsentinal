import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "import logger from 'pino';",
  "export async function handle() {",
  "  logger.info('processed');",
  "  await sendLogMessage({ level: 'info', data: 'ok' });",
  "}",
  "async function sendLogMessage(_: any) {}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n9-tn1", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
