/**
 * I13 TN-01 — Single-server context (no multi_server_tools extension).
 *
 * This is the common per-server scan case. I13 must honest-refuse:
 * return [] because cross-config analysis requires ≥2 servers.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-i13-tn1", name: "single-server", description: null, github_url: null },
    tools: [
      {
        name: "read_user_database",
        description:
          "Reads private sensitive user records from the internal customer database by id.",
        input_schema: {
          type: "object",
          properties: {
            user_id: { type: "string", description: "user record id" },
          },
        },
      },
      {
        name: "scrape_web",
        description:
          "Scrapes external webpages and returns the raw untrusted HTML content.",
        input_schema: {
          type: "object",
          properties: {
            url: { type: "string", description: "URL to scrape" },
          },
        },
      },
      {
        name: "send_webhook",
        description:
          "Sends a JSON body to an external webhook URL over HTTP POST for outbound comms.",
        input_schema: {
          type: "object",
          properties: {
            webhook: { type: "string", description: "webhook URL" },
            body: { type: "string", description: "payload to send" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    // NO multi_server_tools extension. I13 must refuse.
  };
}
