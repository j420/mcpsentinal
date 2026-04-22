/**
 * I13 TP-01 — Classic three-server split.
 *
 * Server A exposes read-user-database (private-data leg).
 * Server B exposes scrape-web (untrusted-content leg).
 * Server C exposes send-webhook (external-comms leg).
 *
 * F1 does NOT fire on any individual server. I13 must merge and fire
 * with rule_id "I13" and a 40-point score cap.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const serverATools: AnalysisContext["tools"] = [
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
  ];
  const serverBTools: AnalysisContext["tools"] = [
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
  ];
  const serverCTools: AnalysisContext["tools"] = [
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
  ];

  // Merged tool set for context.tools (what the engine sees for per-server
  // rules), plus the multi_server_tools extension that I13 consumes.
  const allTools = [...serverATools, ...serverBTools, ...serverCTools];

  const context = {
    server: { id: "srv-i13-tp1", name: "merged-client-config", description: null, github_url: null },
    tools: allTools,
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  } as AnalysisContext;

  (context as unknown as Record<string, unknown>).multi_server_tools = [
    { server_name: "server-a-db", tools: serverATools },
    { server_name: "server-b-web", tools: serverBTools },
    { server_name: "server-c-webhook", tools: serverCTools },
  ];

  return context;
}
