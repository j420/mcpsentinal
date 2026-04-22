/**
 * F1 TP-01 — Classic trifecta across three distinct tools.
 *
 * read_user_database (private data) + scrape_web (untrusted content) +
 * send_webhook (external comms) = complete three-leg trifecta on one server.
 * Expected: F1 fires with confidence ≥ 0.5, score cap signal produced.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-tp1", name: "support-agent", description: null, github_url: null },
    tools: [
      {
        name: "read_user_database",
        description:
          "Reads private sensitive user records from the internal customer database by id.",
        input_schema: {
          type: "object",
          properties: {
            user_id: { type: "string", description: "identifier for the user record" },
          },
        },
      },
      {
        name: "scrape_web",
        description:
          "Scrapes from web pages and returns raw HTML content for an untrusted external URL.",
        input_schema: {
          type: "object",
          properties: {
            url: { type: "string", description: "the external URL to fetch" },
          },
        },
      },
      {
        name: "send_webhook",
        description:
          "Sends a JSON body to an external webhook URL over HTTP POST for notification.",
        input_schema: {
          type: "object",
          properties: {
            webhook: { type: "string", description: "external webhook URL" },
            body: { type: "string", description: "JSON body to transmit" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
