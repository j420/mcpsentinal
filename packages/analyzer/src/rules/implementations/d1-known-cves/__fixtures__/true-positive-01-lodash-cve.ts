import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "lodash",
        version: "4.17.10",
        has_known_cve: true,
        cve_ids: ["CVE-2019-10744"],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
