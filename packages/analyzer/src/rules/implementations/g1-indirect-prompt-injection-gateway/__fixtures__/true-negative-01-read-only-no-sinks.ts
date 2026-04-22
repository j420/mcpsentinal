/**
 * G1 TN-01 — Web scraper alone, no sinks on the server.
 *
 * Single tool that ingests web content. No network-egress / write /
 * execute / modify-config tool on the same server. The gateway
 * precondition is satisfied but the sink precondition is not, so G1
 * must NOT fire. Verifies the capability-pair requirement.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-g1-tn1",
      name: "read-only-browser",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "scrape_webpage",
        description:
          "Scrapes from external web URLs and returns parsed untrusted " +
          "page content for human review. No side effects.",
        input_schema: {
          type: "object",
          properties: {
            url: { type: "string", description: "external URL to fetch" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
