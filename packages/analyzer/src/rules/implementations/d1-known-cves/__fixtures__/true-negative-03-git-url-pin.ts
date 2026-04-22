import type { AnalysisContext } from "../../../../engine.js";

/**
 * Edge case: dependency is pinned via git URL (version resolves to null).
 * Charter requires the rule to silently skip — the evidence chain must
 * never claim a version string the manifest does not contain.
 */
export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "internal-lib",
        version: null,
        has_known_cve: true,
        cve_ids: ["CVE-2023-12345"],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
