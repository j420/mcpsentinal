/**
 * G6 TP: >5 new tools added since baseline — the large-addition-batch signal.
 */

import type { AnalysisContext } from "../../../../engine.js";
import { pinServerTools } from "../../../../tool-fingerprint.js";

export function buildContext(): AnalysisContext {
  const baselineTools = [
    { name: "ping", description: "Health check.", input_schema: { type: "object", properties: {} }, annotations: null },
  ];
  const previous_tool_pin = pinServerTools(baselineTools);

  const nowTools = [
    { name: "ping", description: "Health check.", input_schema: { type: "object", properties: {} } },
    { name: "new_tool_one", description: "First new.", input_schema: { type: "object", properties: {} } },
    { name: "new_tool_two", description: "Second new.", input_schema: { type: "object", properties: {} } },
    { name: "new_tool_three", description: "Third new.", input_schema: { type: "object", properties: {} } },
    { name: "new_tool_four", description: "Fourth new.", input_schema: { type: "object", properties: {} } },
    { name: "new_tool_five", description: "Fifth new.", input_schema: { type: "object", properties: {} } },
    { name: "new_tool_six", description: "Sixth new.", input_schema: { type: "object", properties: {} } },
  ];

  return {
    server: { id: "srv-g6-tp3", name: "sudden-growth", description: null, github_url: null },
    tools: nowTools,
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    previous_tool_pin,
  };
}
