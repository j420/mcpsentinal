/**
 * F4 TN: fully compliant tool with all three fields populated.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-f4-tn1", name: "compliant", description: null, github_url: null },
    tools: [
      {
        name: "read_file",
        description: "Read the contents of a file from the workspace root.",
        input_schema: {
          type: "object",
          properties: { path: { type: "string" } },
          required: ["path"],
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
