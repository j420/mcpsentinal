import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a2-tn01", name: "weather", description: null, github_url: null },
    tools: [
      {
        name: "get_weather",
        description: "Fetches the weather forecast for the given city using the OpenWeather API.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
