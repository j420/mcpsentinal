/**
 * Shape of @modelcontextprotocol/server-brave-search. Provides web and
 * local search via the Brave Search API. Requires BRAVE_API_KEY; no
 * credentials are collected from the client.
 */
import type { BenignFixture } from "../types.js";

export const braveSearchFixture: BenignFixture = {
  id: "anthropic-official/brave-search",
  bucket: "anthropic-official",
  why_benign:
    "Official brave-search server: read-only search tools with well-typed " +
    "parameters. No injection surface beyond the query string which is sent " +
    "as a search param, not executed. Stresses G1 (external content " +
    "ingestion) — this is a gateway, but the server itself is not the " +
    "attacker; a rule that fires on every search-engine MCP would be a " +
    "false positive by construction.",
  context: {
    server: {
      id: "anthropic/brave-search",
      name: "brave-search",
      description:
        "An MCP server implementation that integrates with the Brave Search " +
        "API, providing both web and local search capabilities.",
      github_url:
        "https://github.com/modelcontextprotocol/servers/tree/main/src/brave-search",
    },
    tools: [
      {
        name: "brave_web_search",
        description:
          "Run a web search using the Brave Search API, ideal for general " +
          "information retrieval, news, articles and online content.",
        input_schema: {
          type: "object",
          properties: {
            search_terms: { type: "string", maxLength: 400 },
            count: { type: "number", minimum: 1, maximum: 20 },
            offset: { type: "number", minimum: 0, maximum: 9 },
          },
          required: ["search_terms"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
      {
        name: "brave_local_search",
        description:
          "Search for local businesses and places using the Brave Search " +
          "API. Falls back to web search if no local results are found.",
        input_schema: {
          type: "object",
          properties: {
            search_terms: { type: "string", maxLength: 400 },
            count: { type: "number", minimum: 1, maximum: 20 },
          },
          required: ["search_terms"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
    // Source code omitted: at analyzer runtime many servers are scanned
    // from npm metadata alone, without a source_files fetch. This fixture
    // exercises the description / schema / dependency paths — not the
    // AST taint path. Leaving source_code null is the realistic default.
    source_code: null,
    dependencies: [
      {
        name: "@modelcontextprotocol/sdk",
        version: "1.5.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-01"),
      },
    ],
    connection_metadata: null,
  },
};
