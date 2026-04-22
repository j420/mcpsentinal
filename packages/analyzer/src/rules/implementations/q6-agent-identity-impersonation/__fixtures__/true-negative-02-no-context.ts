/**
 * Q6 TN-02 — Neither source code nor tools metadata.
 * Honest refusal: 0 findings.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "q6-tn02", name: "empty", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
