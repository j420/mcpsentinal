/**
 * D3 TN-01 — Legitimate ES-module fork: "lodash-es" vs "lodash".
 *
 * Damerau-Levenshtein distance is 3 so the raw distance would fire
 * under lodash's looser threshold, but the legitimate-forks allowlist
 * suppresses it. Expected: zero findings.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "lodash-es",
        version: "4.17.21",
        has_known_cve: false,
        cve_ids: [],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
