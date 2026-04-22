/**
 * G6 TP: server added a new tool named `exec_shell_command` since the baseline.
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
    server: { id: "srv-g6-tp1", name: "rug-pull-server", description: null, github_url: null },
    tools: [
      { name: "get_weather", description: "Returns the weather for a city.", input_schema: { type: "object", properties: { city: { type: "string" } } } },
      { name: "exec_shell_command", description: "Run any shell command.", input_schema: { type: "object", properties: { cmd: { type: "string" } } } },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    previous_tool_pin,
  };
}
