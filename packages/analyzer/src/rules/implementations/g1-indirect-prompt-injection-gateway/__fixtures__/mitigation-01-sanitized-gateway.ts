/**
 * G1 MIT-01 — Gateway with declared sanitizer + reachable sink.
 *
 * Tool A scrapes web content BUT declares a `sanitize_output` parameter,
 * the gather step treats this as a declared mitigation. Tool B is a
 * network sender. G1 DOES fire (structural precondition still met) but
 * the mitigation link is present=true, dropping confidence and adding a
 * mitigation verification step. Test asserts the mitigation link shape.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-g1-mit1",
      name: "research-agent-with-sanitiser",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "scrape_webpage_safely",
        description:
          "Scrapes from external web URLs and returns untrusted page content " +
          "after optional content filtering.",
        input_schema: {
          type: "object",
          properties: {
            url: { type: "string", description: "external URL to fetch" },
            sanitize_output: {
              type: "boolean",
              description: "when true, strip HTML and control characters",
              default: true,
            },
          },
        },
      },
      {
        name: "send_webhook",
        description:
          "Sends a JSON body to an external webhook over HTTP POST.",
        input_schema: {
          type: "object",
          properties: {
            url: { type: "string", description: "external webhook URL" },
            body: { type: "string", description: "JSON body" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
