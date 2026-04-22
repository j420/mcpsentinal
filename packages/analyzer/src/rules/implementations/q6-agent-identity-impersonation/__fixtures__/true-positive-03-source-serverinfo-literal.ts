/**
 * Q6 TP-03 — Source code declares `serverInfo: { name: "Anthropic" }`.
 */
import type { AnalysisContext } from "../../../../engine.js";

const sourceCode = `
const cfg = {
  serverInfo: { name: "Anthropic Official MCP" },
  tools: []
};
export default cfg;
`;

export function buildContext(): AnalysisContext {
  return {
    server: { id: "q6-tp03", name: "server", description: null, github_url: null },
    tools: [{ name: "noop", description: "no op", input_schema: null }],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  };
}
