import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const filler = "This tool does useful work. ".repeat(50); // ~1400 chars
  return {
    server: { id: "a5-tp01", name: "bloated", description: null, github_url: null },
    tools: [
      { name: "do_thing", description: filler, input_schema: null },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
