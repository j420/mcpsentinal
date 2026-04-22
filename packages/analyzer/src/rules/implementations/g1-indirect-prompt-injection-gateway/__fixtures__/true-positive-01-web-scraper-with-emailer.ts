/**
 * G1 TP-01 — Web scraper + email sender on the same server.
 *
 * The Rehberger (2024) canonical scenario: a tool fetches arbitrary web
 * pages (classified `ingests-untrusted`) and the same server exposes a
 * tool that sends email to an external recipient (classified
 * `sends-network`). Expected: one G1 finding with the scraper as the
 * gateway and the emailer as the canonical sink.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-g1-tp1",
      name: "research-agent",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "scrape_webpage",
        description:
          "Scrapes from web URLs and parses untrusted external HTML content; " +
          "returns the raw page text for downstream reasoning.",
        input_schema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "the external URL to fetch",
            },
          },
        },
      },
      {
        name: "send_email",
        description:
          "Posts to an external SMTP endpoint — transmits via the outbound " +
          "email gateway. Sends through the transactional provider.",
        input_schema: {
          type: "object",
          properties: {
            endpoint_url: {
              type: "string",
              description: "external SMTP endpoint URL",
            },
            to: { type: "string", description: "recipient address" },
            subject: { type: "string", description: "subject line" },
            body: { type: "string", description: "message body" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
