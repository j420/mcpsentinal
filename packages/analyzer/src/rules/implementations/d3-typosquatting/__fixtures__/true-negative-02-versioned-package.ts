/**
 * D3 TN-02 — Version-suffixed package: "react-18" vs "react".
 *
 * The numeric suffix (`-18`) is a legitimate publisher-versioning
 * convention; the numeric-suffix strip must remove it before comparing
 * against the "react" target. Since the stripped name equals the
 * target, no finding should fire. Expected: zero findings.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "react-18",
        version: "18.2.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
