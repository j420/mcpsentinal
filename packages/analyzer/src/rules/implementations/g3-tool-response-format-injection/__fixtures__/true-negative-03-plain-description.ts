/**
 * TN-03: Plain description with no protocol-mimic content.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "g3-tn03",
      name: "file-reader",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "read_file",
        description:
          "Reads a file from the local filesystem and returns its contents " +
          "as UTF-8 text. Paths are validated against the configured root.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
