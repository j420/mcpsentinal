/**
 * I13 TP-03 — Credential server + scraping server + networking server.
 *
 * A different flavour of cross-config trifecta: the private-data leg
 * is credential-handling (password manager), not database access.
 * The capability-graph should still classify it as the private-data
 * leg (manages-credentials is in PRIVATE_DATA_CAPS).
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const credSrv: AnalysisContext["tools"] = [
    {
      name: "get_secret_by_name",
      description:
        "Returns the value of a stored password, API token, or credential by its logical name.",
      input_schema: {
        type: "object",
        properties: {
          secret_name: { type: "string", description: "logical name of the credential" },
        },
      },
    },
  ];
  const scrapeSrv: AnalysisContext["tools"] = [
    {
      name: "scrape_webpage",
      description:
        "Scrapes from external web pages and ingests from untrusted user content sources.",
      input_schema: {
        type: "object",
        properties: {
          url: { type: "string", description: "webpage URL to scrape" },
        },
      },
    },
  ];
  const egressSrv: AnalysisContext["tools"] = [
    {
      name: "http_post_request",
      description:
        "Issues an outbound HTTP POST to an arbitrary external endpoint with the given body.",
      input_schema: {
        type: "object",
        properties: {
          url: { type: "string", description: "endpoint URL" },
          body: { type: "string", description: "request body" },
        },
      },
    },
  ];

  const allTools = [...credSrv, ...scrapeSrv, ...egressSrv];
  const context = {
    server: { id: "srv-i13-tp3", name: "cred-scrape-egress", description: null, github_url: null },
    tools: allTools,
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  } as AnalysisContext;

  (context as unknown as Record<string, unknown>).multi_server_tools = [
    { server_name: "credential-vault-server", tools: credSrv },
    { server_name: "web-scraper-server", tools: scrapeSrv },
    { server_name: "http-sender-server", tools: egressSrv },
  ];

  return context;
}
