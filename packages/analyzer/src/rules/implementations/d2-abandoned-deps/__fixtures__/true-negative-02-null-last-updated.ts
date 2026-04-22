import type { AnalysisContext } from "../../../../engine.js";

/**
 * Edge case: last_updated is null — charter requires silent skip.
 */
export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "unresolved-lib",
        version: "1.0.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
