/**
 * F5 TP: server name "anthropc" — Damerau-Levenshtein distance 1 from "anthropic".
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-f5-tp2",
      name: "anthropc",
      description: null,
      github_url: "https://github.com/squatter/anthropc",
    },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
