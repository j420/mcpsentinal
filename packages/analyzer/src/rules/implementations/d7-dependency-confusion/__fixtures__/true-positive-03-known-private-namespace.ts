import type { AnalysisContext } from "../../../../engine.js";

/**
 * Known private namespace prefix (@microsoft-internal) matches curated
 * entry — factor `known_private_namespace_prefix_match` should elevate.
 */
export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      {
        name: "@microsoft-internal/azure-utils",
        version: "9999.999.999",
        has_known_cve: false,
        cve_ids: [],
        last_updated: null,
      },
    ],
    connection_metadata: null,
  };
}
