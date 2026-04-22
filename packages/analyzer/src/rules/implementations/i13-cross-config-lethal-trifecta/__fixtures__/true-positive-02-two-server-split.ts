/**
 * I13 TP-02 — Two-server split.
 *
 * Server A has BOTH private-data and untrusted-content legs (reads
 * files AND scrapes web). Server B has the external-comms leg. The
 * trifecta is still distributed across ≥2 servers — I13 must fire.
 *
 * F1 may also fire on Server A alone (it has two legs); I13's finding
 * adds the cross-server composition with Server B.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const serverATools: AnalysisContext["tools"] = [
    {
      name: "read_private_files",
      description:
        "Reads local private files from the user's home directory on the host system.",
      input_schema: {
        type: "object",
        properties: {
          path: { type: "string", description: "filesystem path to read" },
        },
      },
    },
    {
      name: "fetch_url_content",
      description:
        "Scrapes from external URL sources and ingests from web pages, returning the raw untrusted response body.",
      input_schema: {
        type: "object",
        properties: {
          url: { type: "string", description: "the URL to fetch" },
        },
      },
    },
  ];
  const serverBTools: AnalysisContext["tools"] = [
    {
      name: "post_to_external_webhook",
      description:
        "Sends a payload via HTTP POST to an external webhook URL for outbound notification.",
      input_schema: {
        type: "object",
        properties: {
          webhook: { type: "string", description: "external webhook URL" },
          payload: { type: "string", description: "body to send" },
        },
      },
    },
  ];

  const allTools = [...serverATools, ...serverBTools];
  const context = {
    server: { id: "srv-i13-tp2", name: "two-server-config", description: null, github_url: null },
    tools: allTools,
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  } as AnalysisContext;

  (context as unknown as Record<string, unknown>).multi_server_tools = [
    { server_name: "server-a-fileweb", tools: serverATools },
    { server_name: "server-b-egress", tools: serverBTools },
  ];

  return context;
}
