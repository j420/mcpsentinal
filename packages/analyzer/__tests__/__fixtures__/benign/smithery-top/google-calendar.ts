/**
 * Calendar MCP server.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const googleCalendarFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/calendar",
  name: "calendar-bridge",
  why:
    "Calendar MCP. Stresses B3 excessive-parameter-count negative " +
    "(<15 per tool), and K7 long-lived-tokens negative (refresh " +
    "token rotation handled by the OAuth provider, not baked in).",
  description:
    "Calendar MCP server — list and make calendar events for the " +
    "authenticated user.",
  github_url: "https://github.com/community/mcp-calendar",
  tools: [
    {
      name: "list_events",
      description:
        "List events on a specific calendar within a time range.",
      input_schema: {
        type: "object",
        properties: {
          calendar_id: { type: "string", maxLength: 256 },
          time_min: { type: "string", format: "date-time" },
          time_max: { type: "string", format: "date-time" },
          max_results: { type: "integer", minimum: 1, maximum: 250 },
        },
        required: ["calendar_id"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "make_event",
      description: "Make a new event on the specified calendar.",
      input_schema: {
        type: "object",
        properties: {
          calendar_id: { type: "string", maxLength: 256 },
          summary: { type: "string", maxLength: 256 },
          start: { type: "string", format: "date-time" },
          end: { type: "string", format: "date-time" },
          attendees: {
            type: "array",
            items: { type: "string", format: "email" },
            maxItems: 50,
          },
        },
        required: ["calendar_id", "summary", "start", "end"],
        additionalProperties: false,
      },
    },
  ],
});
