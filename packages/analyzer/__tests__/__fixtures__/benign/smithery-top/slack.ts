/**
 * Shape of a community Slack MCP server (distinct from Anthropic's).
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const slackSmitheryFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/slack",
  name: "slack-community",
  why:
    "Community Slack MCP. Stresses A4 shadowing negative (distinct " +
    "from Anthropic's slack tool names), F3 data-flow negative " +
    "(send/read distinct tools), and K6 overly-broad-oauth negative.",
  description:
    "Community Slack MCP — post chat to a channel and list recent " +
    "chat using a Slack bot token. Requests channels:history and " +
    "chat:write scopes only.",
  github_url: "https://github.com/community/mcp-slack",
  tools: [
    {
      name: "post_to_channel",
      description:
        "Post a plain-text or markdown line to a Slack channel the " +
        "bot has been invited to.",
      input_schema: {
        type: "object",
        properties: {
          channel: { type: "string", pattern: "^[CDG][A-Z0-9]{8,24}$" },
          text: { type: "string", maxLength: 40000 },
          thread_ts: { type: "string", pattern: "^[0-9.]+$" },
        },
        required: ["channel", "text"],
        additionalProperties: false,
      },
    },
    {
      name: "recent_chat",
      description:
        "Return the most recent N chat lines from a channel the bot " +
        "is a member of. Paginated by ts cursor.",
      input_schema: {
        type: "object",
        properties: {
          channel: { type: "string", maxLength: 64 },
          limit: { type: "integer", minimum: 1, maximum: 200 },
          cursor: { type: "string", maxLength: 256 },
        },
        required: ["channel"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
});
