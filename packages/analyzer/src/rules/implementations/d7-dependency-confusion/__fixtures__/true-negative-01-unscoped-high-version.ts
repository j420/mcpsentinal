import type { AnalysisContext } from "../../../../engine.js";

/**
 * Unscoped package at high version — D7 applies only to SCOPED packages
 * per Birsan's attack surface.
 */
export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      { name: "big-random-lib", version: "9999.0.0", has_known_cve: false, cve_ids: [], last_updated: null },
    ],
    connection_metadata: null,
  };
}
