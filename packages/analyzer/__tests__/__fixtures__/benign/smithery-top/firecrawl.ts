/**
 * Firecrawl MCP server — scraping at scale.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const firecrawlFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/firecrawl",
  name: "firecrawl",
  why:
    "Firecrawl MCP. Stresses G1 indirect-injection gateway negative " +
    "(no sink — this server only reads; injected content stays " +
    "contained), and A3 suspicious-URL negative.",
  description:
    "Firecrawl MCP — fetch one target into markdown or map a small " +
    "site and return structured pages.",
  github_url: "https://github.com/mendableai/firecrawl-mcp-server",
  tools: [
    {
      name: "fetch_as_markdown",
      description:
        "Fetch one target and return the page as cleaned markdown. " +
        "Binary and large pages (over 5MB) are rejected.",
      input_schema: {
        type: "object",
        properties: {
          target_https: {
            type: "string",
            format: "uri",
            maxLength: 2048,
            pattern: "^https://",
          },
          only_main_content: { type: "boolean" },
        },
        required: ["target_https"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    {
      name: "map_site_targets",
      description:
        "Return a list of targets discovered under a seed target up to " +
        "a configurable depth.",
      input_schema: {
        type: "object",
        properties: {
          seed_https: {
            type: "string",
            format: "uri",
            maxLength: 2048,
            pattern: "^https://",
          },
          max_depth: { type: "integer", minimum: 1, maximum: 5 },
          max_items: { type: "integer", minimum: 1, maximum: 1000 },
        },
        required: ["seed_https"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
  ],
});
