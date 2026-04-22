import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const thirteenMonthsAgo = new Date(Date.now() - 13 * 30 * 24 * 60 * 60 * 1000);
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "old-lib",
        version: "1.2.3",
        has_known_cve: false,
        cve_ids: [],
        last_updated: thirteenMonthsAgo,
      },
    ],
    connection_metadata: null,
  };
}
