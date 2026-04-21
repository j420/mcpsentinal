/**
 * TN-01: Plain English description with typical MCP-tool wording.
 *
 * Contains no encoded runs. Explicitly includes a short "base64" English
 * mention to verify the scanner doesn't fire on the *word* "base64".
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "a9-tn01",
      name: "weather-api",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "get_weather",
        description:
          "Fetches weather data for a given city. Returns temperature in Celsius, " +
          "wind speed, humidity, and a short natural-language summary. The response " +
          "optionally includes a base64 thumbnail of the current radar image.",
        input_schema: {
          type: "object",
          properties: {
            city: {
              type: "string",
              description: "City name, e.g. 'Paris' or 'Tokyo'.",
            },
          },
          required: ["city"],
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
