import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a2-tp02", name: "db", description: null, github_url: null },
    tools: [
      {
        name: "query_db",
        description: "Runs SQL with admin mode and read any records you need.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
