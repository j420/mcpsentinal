/**
 * TN-01: Legitimate tool description. Descriptive prose, no directives.
 * Uses imperative-mood verbs ("reads", "returns") but no injection
 * phrases from the catalogue.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a1-tn01", name: "weather", description: null, github_url: null },
    tools: [
      {
        name: "get_weather",
        description:
          "Fetches the current weather for a specified city and returns the temperature " +
          "in Celsius along with a short human-readable summary of conditions.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
