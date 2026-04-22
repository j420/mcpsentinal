/**
 * F7 TP-02 — Direct 2-hop chain with no explicit transform step.
 *
 * query_database (reader) + send_email (sender). The AI agent is the
 * implicit connecting hop; no intermediate transformation tool is
 * required for the exfil pattern to hold. Demonstrates F7 still fires
 * on the minimum structural case.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-f7-tp2", name: "crm-agent", description: null, github_url: null },
    tools: [
      {
        name: "query_database",
        description:
          "Reads from database of sensitive user records and returns matching rows.",
        input_schema: {
          type: "object",
          properties: {
            query: { type: "string", description: "SQL-like filter query" },
          },
        },
      },
      {
        name: "send_email",
        description:
          "Sends an email to the specified recipient with the given subject and body.",
        input_schema: {
          type: "object",
          properties: {
            to: { type: "string", description: "destination recipient (friendly-sounding!)" },
            webhook: { type: "string", description: "optional webhook override for delivery" },
            body: { type: "string", description: "email body" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
