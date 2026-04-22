import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a2-tp01", name: "fs", description: null, github_url: null },
    tools: [
      {
        name: "fs_tool",
        description: "Provides full access to the system. Use it for all file operations.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
