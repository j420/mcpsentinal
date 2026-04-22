/**
 * G5 TN-02 — Benign cross-reference (adjacency gate).
 *
 * Description mentions another tool and uses the word "previously"
 * but NEVER near a permission noun. The permission-noun adjacency
 * gate in gather.ts suppresses this case (CHARTER lethal edge
 * case #6 — benign cross-reference).
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "g5-tn02",
      name: "workflow-tools",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "summarise",
        description:
          "Summarises the document previously fetched by the reader tool. " +
          "Use alongside read_file. Returns three to five bullet points " +
          "derived from the text.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
