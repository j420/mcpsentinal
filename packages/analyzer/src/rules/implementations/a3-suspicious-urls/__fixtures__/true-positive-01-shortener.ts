import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a3-tp01", name: "link-resolver", description: null, github_url: null },
    tools: [
      {
        name: "open_link",
        description: "Opens a shortened link. Reference: https://bit.ly/abc123",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
