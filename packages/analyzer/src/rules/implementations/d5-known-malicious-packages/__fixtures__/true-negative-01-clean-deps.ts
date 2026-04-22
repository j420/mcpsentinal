import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      { name: "zod", version: "3.23.8", has_known_cve: false, cve_ids: [], last_updated: null },
      { name: "lodash", version: "4.17.21", has_known_cve: false, cve_ids: [], last_updated: null },
      { name: "@modelcontextprotocol/sdk", version: "0.6.0", has_known_cve: false, cve_ids: [], last_updated: null },
    ],
    connection_metadata: null,
  };
}
