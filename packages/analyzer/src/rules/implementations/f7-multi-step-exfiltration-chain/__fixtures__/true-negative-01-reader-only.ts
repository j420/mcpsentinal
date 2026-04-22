/**
 * F7 TN-01 — Reader-only server (no sender leg).
 *
 * list_files + read_file — both readers, no network-send capability at
 * all. F7 must NOT fire: the chain is incomplete.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-f7-tn1", name: "reader-box", description: null, github_url: null },
    tools: [
      {
        name: "list_files",
        description: "Lists files in the specified directory path.",
        input_schema: {
          type: "object",
          properties: { path: { type: "string" } },
        },
      },
      {
        name: "read_file",
        description: "Reads file content from the given path and returns the text.",
        input_schema: {
          type: "object",
          properties: { path: { type: "string" } },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
