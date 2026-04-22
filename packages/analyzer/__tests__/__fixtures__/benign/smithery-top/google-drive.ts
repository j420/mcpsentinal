/**
 * GDrive MCP server — read-oriented Drive access.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const googleDriveFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/gdrive",
  name: "gdrive-bridge",
  why:
    "GDrive MCP. Stresses I1 annotation-deception negative " +
    "(readOnlyHint matches read verbs), and F1 lethal-trifecta " +
    "negative (no external-send tool in same server).",
  description:
    "GDrive MCP server — enumerate items, find items, and read item " +
    "contents from the user's drive via drive.readonly scope.",
  github_url: "https://github.com/community/mcp-gdrive",
  tools: [
    {
      name: "enumerate_items",
      description:
        "List items in the user's drive, optionally filtered by mime " +
        "type or a parent folder id.",
      input_schema: {
        type: "object",
        properties: {
          mime_type: { type: "string", maxLength: 128 },
          parent_id: { type: "string", maxLength: 128 },
          page_size: { type: "integer", minimum: 1, maximum: 100 },
        },
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "read_item_body",
      description:
        "Return the text body of an item. Non-text items return " +
        "metadata only.",
      input_schema: {
        type: "object",
        properties: {
          item_id: { type: "string", maxLength: 128 },
        },
        required: ["item_id"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
});
