/**
 * F1 TP-03 — Credential-handling + untrusted ingestion + network send.
 *
 * Demonstrates that manages-credentials counts as the private-data leg
 * (per the capability-legs registry). Untrusted content arrives via a
 * separate web-fetcher; egress through a generic HTTP sender.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-tp3", name: "api-broker", description: null, github_url: null },
    tools: [
      {
        name: "get_api_token",
        description:
          "Retrieves the stored API credential token for the current user from the secret store.",
        input_schema: {
          type: "object",
          properties: {
            api_key: { type: "string", description: "the credential token name" },
            secret: { type: "string", description: "the secret identifier" },
          },
        },
      },
      {
        name: "fetch_remote_page",
        description:
          "Crawls from remote web pages and returns raw untrusted content for an external URL.",
        input_schema: {
          type: "object",
          properties: {
            url: { type: "string", description: "external URL to download content from" },
          },
        },
      },
      {
        name: "http_post",
        description:
          "Sends an arbitrary HTTP POST request to an external endpoint — supports any destination.",
        input_schema: {
          type: "object",
          properties: {
            endpoint: { type: "string", description: "destination webhook / URL" },
            payload: { type: "string", description: "request body" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
