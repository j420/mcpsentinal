/**
 * Shape of a top-ranked Smithery GitHub Issues MCP server. This mirrors
 * the publicly-listed tool surface for read/manage issues; parameter
 * shapes are typed variants (we don't fabricate tools).
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const githubIssuesFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/github-issues",
  name: "community-issues-tracker",
  why:
    "Top-ranked Smithery issue-tracker server. Stresses A4 tool-name " +
    "shadowing negative (distinct names), F5 namespace squatting " +
    "negative (server name avoids vendor tokens), and I1 annotation-" +
    "deception negative (readOnlyHint matches read-only verbs).",
  description:
    "Community issue-tracker MCP server — list, get, comment, and close " +
    "issues via a personal access token.",
  github_url: "https://github.com/community/mcp-issues-tracker",
  tools: [
    {
      name: "list_repo_issues",
      description:
        "List open or closed issues on a repository. Results are paginated.",
      input_schema: {
        type: "object",
        properties: {
          owner: { type: "string", pattern: "^[a-zA-Z0-9-]+$" },
          repo: { type: "string", pattern: "^[a-zA-Z0-9_.-]+$" },
          state: { type: "string", enum: ["open", "closed", "all"] },
          page: { type: "integer", minimum: 1, maximum: 100 },
        },
        required: ["owner", "repo"],
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    {
      name: "get_issue_detail",
      description:
        "Fetch a single issue with its body, author, labels, and " +
        "assignee list.",
      input_schema: {
        type: "object",
        properties: {
          owner: { type: "string", maxLength: 64 },
          repo: { type: "string", maxLength: 128 },
          issue_number: { type: "integer", minimum: 1 },
        },
        required: ["owner", "repo", "issue_number"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "add_issue_comment",
      description:
        "Post a markdown comment on an existing issue. The comment is " +
        "attributed to the user whose token is configured.",
      input_schema: {
        type: "object",
        properties: {
          owner: { type: "string", maxLength: 64 },
          repo: { type: "string", maxLength: 128 },
          issue_number: { type: "integer", minimum: 1 },
          body: { type: "string", maxLength: 65536 },
        },
        required: ["owner", "repo", "issue_number", "body"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: false, destructiveHint: false },
    },
  ],
});
