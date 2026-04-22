/**
 * F5 TN: server name contains "anthropic" AND github_url is under github.com/anthropics/.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-f5-tn1",
      name: "anthropic-mcp-filesystem",
      description: "Official Anthropic filesystem MCP server",
      github_url: "https://github.com/anthropics/mcp-filesystem",
    },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
