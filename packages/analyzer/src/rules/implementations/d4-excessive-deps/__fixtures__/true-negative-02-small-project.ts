import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      { name: "zod", version: "3.23.8", has_known_cve: false, cve_ids: [], last_updated: null },
      { name: "pino", version: "9.0.0", has_known_cve: false, cve_ids: [], last_updated: null },
    ],
    connection_metadata: null,
  };
}
