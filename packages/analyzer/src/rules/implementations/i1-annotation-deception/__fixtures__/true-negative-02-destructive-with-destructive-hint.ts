/**
 * I1 TN-02 — Destructive tool with destructiveHint: true and readOnlyHint absent.
 *
 * The tool IS destructive — parameter name contains "delete" — but
 * the tool author correctly declared it by setting destructiveHint:
 * true and omitting readOnlyHint. There is no annotation deception
 * here; the annotations match reality, so I1 must NOT fire.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-i1-tn2", name: "honest-destroyer", description: null, github_url: null },
    tools: [
      {
        name: "delete_record",
        description:
          "Removes the specified record from the database.",
        input_schema: {
          type: "object",
          properties: {
            record_id: { type: "string", description: "record to remove" },
          },
        },
        annotations: {
          destructiveHint: true,
          readOnlyHint: false,
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
