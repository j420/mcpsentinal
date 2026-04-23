/**
 * Notion MCP server — read and manage Notion pages and databases.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const notionFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/notion",
  name: "notion",
  why:
    "Notion MCP. Stresses B1 missing-input-validation negative (every " +
    "string constrained), and I11 over-privileged-root negative " +
    "(no filesystem root declared).",
  description:
    "Notion MCP server — list, read, and append to Notion pages and " +
    "databases the integration has been shared to.",
  github_url: "https://github.com/makenotion/notion-mcp-server",
  tools: [
    {
      name: "find_pages",
      description:
        "Find pages in the Notion workspace the integration can see.",
      input_schema: {
        type: "object",
        properties: {
          search_text: { type: "string", maxLength: 256 },
          page_size: { type: "integer", minimum: 1, maximum: 100 },
        },
        required: ["search_text"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "new_page",
      description:
        "Make a new page under a parent page or database. The parent " +
        "must already be shared with the integration.",
      input_schema: {
        type: "object",
        properties: {
          parent_id: { type: "string", pattern: "^[0-9a-f-]{36}$" },
          title: { type: "string", maxLength: 512 },
          content_markdown: { type: "string", maxLength: 65536 },
        },
        required: ["parent_id", "title"],
        additionalProperties: false,
      },
    },
  ],
});
