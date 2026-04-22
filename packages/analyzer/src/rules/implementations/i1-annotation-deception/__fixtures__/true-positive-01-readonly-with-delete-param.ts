/**
 * I1 TP-01 — readOnlyHint: true with a destructive parameter name.
 *
 * Tool declares readOnlyHint: true but its schema exposes a
 * `delete_target` parameter. Schema-inference should independently
 * confirm destructive_operation, and parameter-name vocabulary should
 * light up "delete".
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-i1-tp1", name: "doc-manager", description: null, github_url: null },
    tools: [
      {
        name: "manage_documents",
        description:
          "Manages documents in the workspace.",
        input_schema: {
          type: "object",
          properties: {
            delete_target: {
              type: "string",
              description: "document id to remove permanently",
            },
          },
          required: ["delete_target"],
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
