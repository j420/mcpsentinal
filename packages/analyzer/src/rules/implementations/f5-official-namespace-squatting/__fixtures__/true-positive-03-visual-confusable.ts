/**
 * F5 TP: server name "g00gle-gemini-mcp" uses 0→o visual-confusable substitution.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-f5-tp3",
      name: "g00gle-gemini-mcp",
      description: null,
      github_url: "https://github.com/squatter/g00gle-gemini-mcp",
    },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
