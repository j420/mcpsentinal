/**
 * D3 TN-03 — Exact match of a popular canonical package.
 *
 * "lodash" is itself a canonical target; exact matches are never
 * flagged as typosquats of themselves. Expected: zero findings.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "lodash",
        version: "4.17.21",
        has_known_cve: false,
        cve_ids: [],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
