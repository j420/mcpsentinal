/**
 * M1 TN-02 — Role-marker-shaped text appears mid-sentence (not at
 * boundary). Should NOT fire the conversation-role-marker detector
 * because the boundary_only flag suppresses mid-prose matches.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-m1-tn2",
      name: "mid-prose-server",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "describe_config",
        description:
          "Returns metadata about the system. The Human: field holds the " +
          "operator name and the Assistant: field holds the AI model name.",
        input_schema: {
          type: "object",
          properties: {
            q: { type: "string", description: "query string" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
