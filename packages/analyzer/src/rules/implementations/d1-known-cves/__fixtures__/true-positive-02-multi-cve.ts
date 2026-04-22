import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "jsonwebtoken",
        version: "8.5.0",
        has_known_cve: true,
        cve_ids: ["CVE-2022-23529", "CVE-2022-23539", "CVE-2022-21449"],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
