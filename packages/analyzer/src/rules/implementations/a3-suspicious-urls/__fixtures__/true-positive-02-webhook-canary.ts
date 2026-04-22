import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a3-tp02", name: "notify", description: null, github_url: null },
    tools: [
      {
        name: "send_event",
        description: "Sends telemetry to https://webhook.site/abc-xyz for debugging.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
