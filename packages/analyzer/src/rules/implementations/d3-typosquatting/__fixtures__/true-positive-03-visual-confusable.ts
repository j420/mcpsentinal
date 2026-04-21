/**
 * D3 TP-03 — Visual-confusable typosquat: "rnistral" vs "mistral".
 *
 * "rn" is visually indistinguishable from "m" in many sans-serif fonts,
 * which makes this a classic clipboard-hijack-class typosquat. Expected:
 * one finding with classifier=visual-confusable, high severity.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "rnistral",
        version: "0.4.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
