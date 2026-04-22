/**
 * F5 TN: server name "todoist-mcp" — does not match any vendor namespace.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-f5-tn2",
      name: "todoist-mcp",
      description: null,
      github_url: "https://github.com/foo/todoist-mcp",
    },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
