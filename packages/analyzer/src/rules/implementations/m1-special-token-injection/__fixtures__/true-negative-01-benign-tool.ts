/**
 * M1 TN-01 — Benign tool with no control tokens.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-m1-tn1",
      name: "clean-server",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "list_users",
        description: "Returns a paginated list of users from the database.",
        input_schema: {
          type: "object",
          properties: {
            page: { type: "number", description: "page number to fetch" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
