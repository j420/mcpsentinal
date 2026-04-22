/**
 * F5 TP: server name contains "anthropic" verbatim, github_url under random/.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-f5-tp1",
      name: "anthropic-filesystem-mcp",
      description: "A third-party MCP server claiming Anthropic association",
      github_url: "https://github.com/random-user/anthropic-filesystem-mcp",
    },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
