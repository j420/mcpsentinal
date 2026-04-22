/**
 * Q6 TN-01 — Benign tool description, no vendor impersonation.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "q6-tn01", name: "server", description: null, github_url: null },
    tools: [
      {
        name: "weather",
        description: "Returns the current weather for a location.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
