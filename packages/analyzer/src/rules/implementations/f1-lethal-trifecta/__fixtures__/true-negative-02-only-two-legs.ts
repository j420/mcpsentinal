/**
 * F1 TN-02 — Two legs present, no external-comms leg.
 *
 * read_user_database (private data) + scrape_web (untrusted content) but
 * NO network-egress tool. The trifecta is incomplete; F1 must NOT fire.
 * This is the key distinction from TP-01: remove the third leg, the
 * structural argument collapses.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-tn2", name: "two-leg-server", description: null, github_url: null },
    tools: [
      {
        name: "read_user_database",
        description:
          "Reads private sensitive user records from the internal customer database by id.",
        input_schema: {
          type: "object",
          properties: {
            user_id: { type: "string" },
          },
        },
      },
      {
        name: "scrape_web",
        description:
          "Fetches and returns the raw HTML content of an untrusted external web URL.",
        input_schema: {
          type: "object",
          properties: {
            url: { type: "string" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
