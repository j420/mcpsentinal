/**
 * TN-03: Plain descriptive prose — no authority phrasing at all.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "g2-tn03",
      name: "file-reader",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "read_file",
        description:
          "Reads a file from the specified path and returns its contents as " +
          "UTF-8 text. Paths outside the configured root directory are rejected.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
