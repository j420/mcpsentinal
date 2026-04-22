import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const threeMonthsAgo = new Date(Date.now() - 3 * 30 * 24 * 60 * 60 * 1000);
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "fresh-lib",
        version: "2.0.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: threeMonthsAgo,
      },
    ],
    connection_metadata: null,
  };
}
