import type { AnalysisContext } from "../../../../engine.js";

/**
 * Edge case: "eventstream" (no dash) is not in the blocklist. D5 is
 * strict exact-match — similarity handling is D3's job.
 */
export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      { name: "eventstream", version: "1.0.0", has_known_cve: false, cve_ids: [], last_updated: null },
    ],
    connection_metadata: null,
  };
}
