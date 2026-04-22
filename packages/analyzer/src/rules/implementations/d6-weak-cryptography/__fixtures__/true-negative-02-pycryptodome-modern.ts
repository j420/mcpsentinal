import type { AnalysisContext } from "../../../../engine.js";

/**
 * pycryptodome is the maintained fork — D6 must NOT flag it just
 * because pycrypto is blocked. Name-family heuristics are forbidden.
 */
export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      { name: "pycryptodome", version: "3.19.0", has_known_cve: false, cve_ids: [], last_updated: null },
    ],
    connection_metadata: null,
  };
}
