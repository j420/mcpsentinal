/**
 * G6 TN: tool set identical to baseline — no drift to flag.
 */

import type { AnalysisContext } from "../../../../engine.js";
import { pinServerTools } from "../../../../tool-fingerprint.js";

export function buildContext(): AnalysisContext {
  const baselineTools = [
    {
      name: "get_weather",
      description: "Returns the weather for a city.",
      input_schema: { type: "object", properties: { city: { type: "string" } } },
      annotations: null,
    },
  ];
  const previous_tool_pin = pinServerTools(baselineTools);

  return {
    server: { id: "srv-g6-tn1", name: "stable-server", description: null, github_url: null },
    tools: [
      {
        name: "get_weather",
        description: "Returns the weather for a city.",
        input_schema: { type: "object", properties: { city: { type: "string" } } },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    previous_tool_pin,
  };
}
