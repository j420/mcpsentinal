/**
 * H2 TN-01 — Silent skip path.
 *
 * No live initialize_metadata (scanner ran from static source
 * inspection only). server.name is a plain identifier with no
 * anomalies. H2 must return zero findings — silent skip.
 *
 * Covers CHARTER lethal edge case #7 (null metadata must not fire).
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "h2-tn01",
      name: "mcp-filesystem",
      description: null,
      github_url: null,
    },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    // intentionally no initialize_metadata
  };
}
