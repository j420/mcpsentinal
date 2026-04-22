/**
 * G5 TN-01 — Plain descriptive tool.
 *
 * Legitimate tool description declaring its own scope explicitly.
 * No prior-approval phrases match at all.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "g5-tn01",
      name: "weather-tools",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "get_weather",
        description:
          "Fetches the current weather for a city using the OpenWeatherMap " +
          "API. Requires the OPENWEATHER_API_KEY environment variable and " +
          "network egress to api.openweathermap.org.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
