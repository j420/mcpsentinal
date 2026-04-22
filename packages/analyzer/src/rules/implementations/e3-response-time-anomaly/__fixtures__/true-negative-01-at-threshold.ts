import type { AnalysisContext } from "../../../../engine.js";

/**
 * Exactly 10,000ms — not over threshold (strict >).
 */
export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: {
      auth_required: true,
      transport: "https",
      response_time_ms: 10_000,
    },
  };
}
