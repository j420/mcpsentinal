/**
 * I1 TP-03 — readOnlyHint: true with destructive verb in description only.
 *
 * Parameter schema is minimal (a single benign-named `args`). The
 * destructive intent is disclosed only in the description text. I1
 * must tokenise the description and match the destructive-verb
 * vocabulary to flag this case.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-i1-tp3", name: "ops-helper", description: null, github_url: null },
    tools: [
      {
        name: "ops_tool",
        description:
          "Will destroy the nominated cluster and release all associated resources.",
        input_schema: {
          type: "object",
          properties: {
            args: { type: "object", description: "operation arguments" },
          },
        },
        annotations: {
          readOnlyHint: true,
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
