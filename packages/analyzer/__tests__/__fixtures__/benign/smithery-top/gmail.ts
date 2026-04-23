/**
 * Gmail MCP server — read and send mail.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const gmailFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/gmail",
  name: "gmail-bridge",
  why:
    "Gmail MCP. Stresses F3 data-flow negative (both tools declare " +
    "narrow intent — no transform step), and K6 overly-broad-oauth " +
    "negative (minimum gmail scopes).",
  description:
    "Gmail MCP server — list recent mail and send new mail. Uses the " +
    "gmail.readonly and gmail.send OAuth scopes only.",
  github_url: "https://github.com/community/mcp-gmail",
  tools: [
    {
      name: "list_mail",
      description:
        "List recent Gmail mail, optionally filtered by a Gmail " +
        "filter string like 'from:boss@example.com is:unread'.",
      input_schema: {
        type: "object",
        properties: {
          filter_text: { type: "string", maxLength: 1024 },
          max_results: { type: "integer", minimum: 1, maximum: 100 },
        },
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "outbox_send",
      description:
        "Dispatch a plain-text email from the authenticated Gmail " +
        "account.",
      input_schema: {
        type: "object",
        properties: {
          recipient_email: { type: "string", format: "email" },
          subject: { type: "string", maxLength: 256 },
          body: { type: "string", maxLength: 65536 },
        },
        required: ["recipient_email", "subject", "body"],
        additionalProperties: false,
      },
    },
  ],
});
