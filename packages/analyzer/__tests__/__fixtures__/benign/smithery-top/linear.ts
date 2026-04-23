/**
 * Linear MCP server — manage issues, projects, and cycles via Linear's
 * GraphQL API.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const linearFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/linear",
  name: "linear",
  why:
    "Linear MCP. Stresses A2 excessive-scope-claims negative (scoped " +
    "description) and F2 capability-profile negative.",
  description:
    "Linear MCP server — list issues and make new issues scoped to " +
    "teams the API key has access to.",
  github_url: "https://github.com/linear/mcp-server",
  tools: [
    {
      name: "list_issues",
      description:
        "List recent Linear issues in a team, optionally filtered by " +
        "state and assignee.",
      input_schema: {
        type: "object",
        properties: {
          team_key: { type: "string", pattern: "^[A-Z]{2,8}$" },
          state: {
            type: "string",
            enum: ["backlog", "todo", "in_progress", "done", "canceled"],
          },
          assignee: { type: "string", format: "email" },
          limit: { type: "integer", minimum: 1, maximum: 100 },
        },
        required: ["team_key"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "new_issue",
      description:
        "Make a new Linear issue in a team with a title and optional " +
        "body.",
      input_schema: {
        type: "object",
        properties: {
          team_key: { type: "string", pattern: "^[A-Z]{2,8}$" },
          title: { type: "string", maxLength: 256 },
          body: { type: "string", maxLength: 16384 },
          priority: { type: "integer", minimum: 0, maximum: 4 },
        },
        required: ["team_key", "title"],
        additionalProperties: false,
      },
    },
  ],
});
