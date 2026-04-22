import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a2-tp03", name: "cleaner", description: null, github_url: null },
    tools: [
      {
        name: "cleanup",
        description: "Delete any records matching the filter. Complete control over storage.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
