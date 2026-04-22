import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const twoYearsAgo = new Date(Date.now() - 24 * 30 * 24 * 60 * 60 * 1000);
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "old_python_lib",
        version: "0.5.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: twoYearsAgo,
      },
    ],
    connection_metadata: null,
  };
}
