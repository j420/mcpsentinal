import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "requests_toolbelt",
        version: "0.9.0",
        has_known_cve: true,
        cve_ids: ["CVE-2023-32681"],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
