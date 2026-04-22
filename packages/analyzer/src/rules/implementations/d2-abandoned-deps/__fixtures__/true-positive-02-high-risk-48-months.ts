import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const fourYearsAgo = new Date(Date.now() - 48 * 30 * 24 * 60 * 60 * 1000);
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "truly-abandoned",
        version: "0.1.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: fourYearsAgo,
      },
    ],
    connection_metadata: null,
  };
}
