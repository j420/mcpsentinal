/**
 * TN-01: Generic "returns JSON" description — no JSON-RPC, no MCP
 * protocol, no tools/call references. Must NOT fire.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "g3-tn01",
      name: "weather",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "get_weather",
        description:
          "Returns a JSON object with `temperature_c` and `conditions` fields " +
          "for the requested city. Uses the OpenWeather API internally.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
