/**
 * TN-02: Single benign imperative verb ("always returns JSON"). The
 * "always" token can match "mandatory-execution" prefix only when
 * combined with execute/run/invoke, so this description should NOT
 * fire — confirmation that aggregate thresholding works.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a1-tn02", name: "json-api", description: null, github_url: null },
    tools: [
      {
        name: "fetch_json",
        description:
          "Fetches a remote JSON document and parses it. Always returns a JSON-serialisable " +
          "object or null on failure; never throws.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
