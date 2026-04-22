import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: {
      auth_required: false,
      transport: "sse",
      response_time_ms: 340,
    },
  };
}
