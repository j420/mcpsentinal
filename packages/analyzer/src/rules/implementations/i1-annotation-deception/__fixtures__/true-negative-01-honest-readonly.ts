/**
 * I1 TN-01 — Honest read-only tool.
 *
 * readOnlyHint: true matches the tool's actual capability: no
 * destructive verbs in name, description, or parameters. I1 must
 * NOT fire — the annotation is truthful.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-i1-tn1", name: "read-only-docs", description: null, github_url: null },
    tools: [
      {
        name: "fetch_document",
        description:
          "Returns the content of a document by id. Purely read-only, no side effects.",
        input_schema: {
          type: "object",
          properties: {
            document_id: { type: "string", description: "document identifier" },
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
