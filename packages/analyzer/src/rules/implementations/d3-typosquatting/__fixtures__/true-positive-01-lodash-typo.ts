/**
 * D3 TP-01 — Classic npm typosquat: "lodahs" vs "lodash".
 *
 * The confirmed-typosquat registry contains `lodahs` as a known
 * malicious shadow of `lodash`. Expected: single finding, critical
 * severity, classifier=confirmed-typosquat.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "lodahs",
        version: "4.17.21",
        has_known_cve: false,
        cve_ids: [],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
