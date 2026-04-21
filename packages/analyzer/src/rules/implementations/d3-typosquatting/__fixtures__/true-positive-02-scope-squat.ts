/**
 * D3 TP-02 — Scope squat of @modelcontextprotocol/sdk.
 *
 * Expected: one finding with classifier=confirmed-typosquat (this name
 * is also explicitly listed in CONFIRMED_TYPOSQUATS), critical severity.
 * Even independent of the advisory registry, the scope-squat detector
 * alone would fire on this name.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "@mcp/sdk",
        version: "1.2.3",
        has_known_cve: false,
        cve_ids: [],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
