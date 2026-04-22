import type { AnalysisContext } from "../../../../engine.js";

/**
 * Edge case: auditor flagged has_known_cve=true but did not populate
 * cve_ids. Charter requires the rule to skip — we never guess an id.
 */
export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "express",
        version: "4.18.2",
        has_known_cve: true,
        cve_ids: [],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
