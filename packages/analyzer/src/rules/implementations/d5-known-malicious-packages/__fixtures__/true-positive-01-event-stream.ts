import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      { name: "event-stream", version: "3.3.6", has_known_cve: false, cve_ids: [], last_updated: null },
    ],
    connection_metadata: null,
  };
}
