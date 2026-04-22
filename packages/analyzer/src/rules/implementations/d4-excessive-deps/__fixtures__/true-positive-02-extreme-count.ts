import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const deps = Array.from({ length: 250 }, (_, i) => ({
    name: `dep${i}`,
    version: "1.0.0",
    has_known_cve: false,
    cve_ids: [],
    last_updated: null,
  }));
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: deps,
    connection_metadata: null,
  };
}
