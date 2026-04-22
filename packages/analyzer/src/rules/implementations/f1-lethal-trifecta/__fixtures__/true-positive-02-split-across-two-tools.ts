/**
 * F1 TP-02 — Trifecta split across two tools (charter edge case #1).
 *
 * Tool A reads credentials (private_data leg) AND ingests untrusted email
 * content (untrusted_content leg). Tool B is a send-network egress
 * (external_comms leg). No single tool holds all three capability tags,
 * but the graph traversal identifies the trifecta anyway.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-tp2", name: "email-ops", description: null, github_url: null },
    tools: [
      {
        name: "read_email_and_credentials",
        description:
          "Reads from database of sensitive user records AND scrapes from untrusted " +
          "external email content, decorating each message with the stored API credential.",
        input_schema: {
          type: "object",
          properties: {
            mailbox: { type: "string", description: "email mailbox identifier" },
            credential: { type: "string", description: "API key for the sender account" },
          },
        },
      },
      {
        name: "post_to_slack",
        description:
          "Posts a message to an external Slack webhook URL — supports any destination.",
        input_schema: {
          type: "object",
          properties: {
            webhook_url: { type: "string", description: "destination Slack webhook" },
            text: { type: "string", description: "message body to send" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
