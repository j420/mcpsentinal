/**
 * Shape of @modelcontextprotocol/server-fetch (Python ref). Fetches web
 * content, with a user_agent override and a max_length guard.
 */
import type { BenignFixture } from "../types.js";

export const fetchFixture: BenignFixture = {
  id: "anthropic-official/fetch",
  bucket: "anthropic-official",
  why_benign:
    "Official fetch server (python ref). Single fetch tool bounded by " +
    "max_length + robots.txt honored by default. Stresses G1 (this IS a " +
    "content-ingestion gateway) — but the server is a benign user-directed " +
    "tool, not an attack surface on its own.",
  context: {
    server: {
      id: "anthropic/fetch",
      name: "fetch",
      description:
        "A Model Context Protocol server that provides web content fetching " +
        "capabilities. It enables LLMs to retrieve and process content from " +
        "web pages, converting HTML to markdown for easier consumption.",
      github_url:
        "https://github.com/modelcontextprotocol/servers/tree/main/src/fetch",
    },
    tools: [
      {
        name: "fetch_page",
        description:
          "Retrieve a page from the internet and return the contents as " +
          "markdown. Honours robots.txt by default. Length is bounded by " +
          "the max_length parameter.",
        input_schema: {
          type: "object",
          properties: {
            target: { type: "string", format: "uri" },
            max_length: { type: "integer", minimum: 0, maximum: 1000000 },
            start_index: { type: "integer", minimum: 0 },
            raw: { type: "boolean" },
          },
          required: ["target"],
          additionalProperties: false,
        },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: true,
        },
      },
    ],
    // Python source dropped — L3 misreads `from X import Y` as a
    // Dockerfile FROM instruction. The fetch server's safety story is
    // robots.txt + bounded max_length, reflected in the tool schema above.
    source_code: null,
    dependencies: [
      {
        name: "mcp",
        version: "1.2.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-01"),
      },
      {
        name: "httpx",
        version: "0.27.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-15"),
      },
      {
        name: "markdownify",
        version: "0.12.1",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-01-20"),
      },
    ],
    connection_metadata: null,
  },
};
