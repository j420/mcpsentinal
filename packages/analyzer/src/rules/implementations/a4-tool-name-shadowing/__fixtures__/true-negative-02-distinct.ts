import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a4-tn02", name: "weather", description: null, github_url: null },
    tools: [
      { name: "get_weather_forecast", description: "Gets the weather.", input_schema: null },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
