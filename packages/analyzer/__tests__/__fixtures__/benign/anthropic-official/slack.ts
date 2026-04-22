/**
 * Shape of @modelcontextprotocol/server-slack. Slack workspace integration
 * with channel listing, messaging, and reactions. Uses a bot token from env.
 */
import type { BenignFixture } from "../types.js";

export const slackFixture: BenignFixture = {
  id: "anthropic-official/slack",
  bucket: "anthropic-official",
  why_benign:
    "Official slack server. Bot token sourced from env (SLACK_BOT_TOKEN), " +
    "never solicited over MCP. Channel / message read + post tools are " +
    "scoped to the bot's OAuth grant; the server itself does not request " +
    "additional scopes over MCP. Tests F1/F7 — read+send profile alone is " +
    "not the lethal trifecta without an untrusted-content ingestion third " +
    "leg.",
  context: {
    server: {
      id: "anthropic/slack",
      name: "slack",
      description:
        "MCP Server for the Slack API, enabling Claude to list channels, " +
        "read messages, post messages and add reactions on behalf of an " +
        "authorised Slack app.",
      github_url:
        "https://github.com/modelcontextprotocol/servers/tree/main/src/slack",
    },
    tools: [
      {
        name: "slack_list_channels",
        description:
          "List public channels in the workspace. Supports pagination via a " +
          "cursor token.",
        input_schema: {
          type: "object",
          properties: {
            limit: { type: "number", minimum: 1, maximum: 200 },
            cursor: { type: "string", maxLength: 128 },
          },
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
      {
        name: "slack_post_message",
        description:
          "Post a new message to a Slack channel. The bot must already be a " +
          "member of the channel.",
        input_schema: {
          type: "object",
          properties: {
            channel_id: { type: "string", pattern: "^[CGDU][A-Z0-9]+$" },
            text: { type: "string", maxLength: 40000 },
          },
          required: ["channel_id", "text"],
          additionalProperties: false,
        },
      },
      {
        name: "slack_reply_to_thread",
        description:
          "Reply to a specific message thread. The thread is identified by " +
          "the parent message's timestamp (thread_ts).",
        input_schema: {
          type: "object",
          properties: {
            channel_id: { type: "string", pattern: "^[CGDU][A-Z0-9]+$" },
            thread_ts: { type: "string", pattern: "^[0-9]+\\.[0-9]+$" },
            text: { type: "string", maxLength: 40000 },
          },
          required: ["channel_id", "thread_ts", "text"],
          additionalProperties: false,
        },
      },
      {
        name: "slack_add_reaction",
        description:
          "Add a reaction emoji to an existing message.",
        input_schema: {
          type: "object",
          properties: {
            channel_id: { type: "string", pattern: "^[CGDU][A-Z0-9]+$" },
            timestamp: { type: "string", pattern: "^[0-9]+\\.[0-9]+$" },
            reaction: { type: "string", pattern: "^[a-z0-9_+-]+$", maxLength: 64 },
          },
          required: ["channel_id", "timestamp", "reaction"],
          additionalProperties: false,
        },
      },
      {
        name: "slack_get_channel_history",
        description:
          "Retrieve recent messages from a Slack channel up to a pagination " +
          "limit.",
        input_schema: {
          type: "object",
          properties: {
            channel_id: { type: "string", pattern: "^[CGDU][A-Z0-9]+$" },
            limit: { type: "number", minimum: 1, maximum: 200 },
          },
          required: ["channel_id"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
    // AnalysisContext source_code is left null for this fixture: the
    // real analyzer input for Slack would come from npm package
    // metadata + MCP tools/list without a source_files fetch. This
    // keeps the A/B/F/D signal clean without hand-rolling a taint
    // chain around the bot token, which itself is not the point of
    // this fixture.
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
