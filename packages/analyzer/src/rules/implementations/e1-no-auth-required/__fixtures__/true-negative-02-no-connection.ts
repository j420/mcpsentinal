import type { AnalysisContext } from "../../../../engine.js";

/**
 * Charter edge case: connection_metadata=null (stdio-only server or
 * scanner failed to connect). Rule must silently skip.
 */
export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
