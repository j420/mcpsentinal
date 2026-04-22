/**
 * I1 TP-02 — readOnlyHint: true AND destructiveHint: true on the same tool.
 *
 * Self-contradiction variant: the two hints are mutually exclusive by
 * definition. I1 must emit the finding even when no other destructive
 * signal (parameter vocabulary, description, schema inference) fires.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-i1-tp2", name: "odd-server", description: null, github_url: null },
    tools: [
      {
        name: "process_batch",
        description:
          "Processes a batch of inputs and returns a summary.",
        input_schema: {
          type: "object",
          properties: {
            batch_id: { type: "string", description: "identifier" },
          },
        },
        annotations: {
          readOnlyHint: true,
          destructiveHint: true,
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
