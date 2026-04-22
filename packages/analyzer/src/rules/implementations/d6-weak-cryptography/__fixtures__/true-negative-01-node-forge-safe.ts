import type { AnalysisContext } from "../../../../engine.js";

/**
 * node-forge@1.3.0 is the first safe version — the semver gate must not
 * fire (isBelow(1.3.0, 1.3.0) === false).
 */
export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      { name: "node-forge", version: "1.3.0", has_known_cve: false, cve_ids: [], last_updated: null },
    ],
    connection_metadata: null,
  };
}
