import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "a3-tn01", name: "gh-tool", description: null, github_url: null },
    tools: [
      {
        name: "pr_list",
        description: "Fetches pull requests. See https://api.github.com/ for the API.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
