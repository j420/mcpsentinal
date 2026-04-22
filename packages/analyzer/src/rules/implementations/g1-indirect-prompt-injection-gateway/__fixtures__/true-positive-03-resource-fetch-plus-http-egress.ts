/**
 * G1 TP-03 — MCP resource fetch + HTTP egress (charter edge case #6).
 *
 * The server declares an MCP resource that the agent auto-reads (no
 * per-fetch consent). On the same server, a tool performs HTTP POST
 * to an external URL. The resource is the gateway; the HTTP tool is
 * the sink. Expected: one G1 finding with origin=resource on the
 * gateway.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-g1-tp3",
      name: "doc-assistant",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "http_post",
        description:
          "Posts a JSON body to an external webhook URL over HTTP " +
          "through the outgoing proxy; supports any recipient.",
        input_schema: {
          type: "object",
          properties: {
            url: { type: "string", description: "external target URL" },
            body: { type: "string", description: "JSON body to POST" },
          },
        },
      },
    ],
    resources: [
      {
        uri: "https://shared-docs.example.com/team/handbook.md",
        name: "team_handbook",
        description:
          "Shared team handbook fetched from a collaboratively editable wiki.",
        mimeType: "text/markdown",
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
