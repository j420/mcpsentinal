/**
 * H3 TN: single-agent tool with no inter-agent vocabulary.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-h3-tn2", name: "weather-service", description: null, github_url: null },
    tools: [
      {
        name: "get_weather",
        description: "Returns current weather for a city.",
        input_schema: { type: "object", properties: { city: { type: "string" } } },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
