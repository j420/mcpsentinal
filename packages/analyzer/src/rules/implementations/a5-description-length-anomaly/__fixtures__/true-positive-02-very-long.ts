import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const prose = "Some explanation that goes on and on without saying much. ".repeat(100); // ~5800 chars
  return {
    server: { id: "a5-tp02", name: "chatty", description: null, github_url: null },
    tools: [
      { name: "verbose_tool", description: prose, input_schema: null },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
