/**
 * Sentry MCP server — error tracking event and issue lookups.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const sentryFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/sentry",
  name: "sentry",
  why:
    "Sentry MCP. Stresses B6 additional-properties negative (every " +
    "schema sets additionalProperties:false), and E4 excessive tool " +
    "count negative.",
  description:
    "Sentry MCP server — look up Sentry projects for errors, issues, " +
    "and events. Read-oriented plus comment posting.",
  github_url: "https://github.com/getsentry/sentry-mcp",
  tools: [
    {
      name: "list_projects",
      description: "List Sentry projects for the organization.",
      input_schema: {
        type: "object",
        properties: {
          organization: { type: "string", maxLength: 64 },
        },
        required: ["organization"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "find_issues",
      description:
        "Look up Sentry issues by project and filter expression.",
      input_schema: {
        type: "object",
        properties: {
          project: { type: "string", maxLength: 128 },
          filter_text: { type: "string", maxLength: 512 },
          limit: { type: "integer", minimum: 1, maximum: 100 },
        },
        required: ["project", "filter_text"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true },
    },
    {
      name: "comment_on_issue",
      description: "Post a comment on a Sentry issue.",
      input_schema: {
        type: "object",
        properties: {
          issue_id: { type: "string", pattern: "^[0-9]+$" },
          body: { type: "string", maxLength: 8192 },
        },
        required: ["issue_id", "body"],
        additionalProperties: false,
      },
    },
  ],
});
