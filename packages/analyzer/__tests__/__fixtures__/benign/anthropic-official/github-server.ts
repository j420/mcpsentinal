/**
 * Shape of @modelcontextprotocol/server-github. Read-only GitHub metadata
 * access and issue management. Token from env (GITHUB_PERSONAL_ACCESS_TOKEN).
 */
import type { BenignFixture } from "../types.js";

export const githubServerFixture: BenignFixture = {
  id: "anthropic-official/github",
  bucket: "anthropic-official",
  why_benign:
    "Official github server — issues, PRs, file contents. Token sourced " +
    "from env. Read + write but scoped to what the token grants, not " +
    "escalated over MCP. Stresses F1/F7 (read + send) and A4 name " +
    "shadowing — 'search_issues' / 'create_pull_request' etc. do not " +
    "shadow Anthropic's canonical tool names.",
  context: {
    server: {
      id: "anthropic/github",
      name: "github",
      description:
        "An MCP server that integrates with the GitHub API, providing file " +
        "operations, repository management, search capabilities and more.",
      github_url:
        "https://github.com/modelcontextprotocol/servers/tree/main/src/github",
    },
    tools: [
      {
        name: "create_or_update_file",
        description:
          "Create or update a single file in a repository, committing with " +
          "the supplied message on the specified branch.",
        input_schema: {
          type: "object",
          properties: {
            owner: { type: "string", pattern: "^[a-zA-Z0-9-]+$" },
            repo: { type: "string", pattern: "^[a-zA-Z0-9_.-]+$" },
            path: { type: "string" },
            content: { type: "string" },
            message: { type: "string", maxLength: 512 },
            branch: { type: "string", maxLength: 128 },
          },
          required: ["owner", "repo", "path", "content", "message", "branch"],
          additionalProperties: false,
        },
      },
      {
        name: "search_repositories",
        description:
          "Search for GitHub repositories. Supports the same query syntax " +
          "as the GitHub Search UI.",
        input_schema: {
          type: "object",
          properties: {
            query: { type: "string", maxLength: 512 },
            page: { type: "integer", minimum: 1 },
            perPage: { type: "integer", minimum: 1, maximum: 100 },
          },
          required: ["query"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
      {
        name: "get_file_contents",
        description:
          "Read the contents of a file from a repository on a specific ref.",
        input_schema: {
          type: "object",
          properties: {
            owner: { type: "string" },
            repo: { type: "string" },
            path: { type: "string" },
            branch: { type: "string" },
          },
          required: ["owner", "repo", "path"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true },
      },
      {
        name: "create_issue",
        description:
          "Create a new issue on a repository with the given title, body " +
          "and labels.",
        input_schema: {
          type: "object",
          properties: {
            owner: { type: "string" },
            repo: { type: "string" },
            title: { type: "string", maxLength: 256 },
            body: { type: "string", maxLength: 65536 },
            labels: {
              type: "array",
              items: { type: "string" },
              maxItems: 16,
            },
          },
          required: ["owner", "repo", "title"],
          additionalProperties: false,
        },
      },
      {
        name: "search_issues",
        description:
          "Search for GitHub issues and pull requests across repositories.",
        input_schema: {
          type: "object",
          properties: {
            q: { type: "string", maxLength: 512 },
            sort: {
              type: "string",
              enum: ["comments", "created", "updated"],
            },
            order: { type: "string", enum: ["asc", "desc"] },
          },
          required: ["q"],
          additionalProperties: false,
        },
      },
    ],
    source_code: `
      const TOKEN = process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
      if (!TOKEN) throw new Error("GITHUB_PERSONAL_ACCESS_TOKEN is required");

      const API_BASE = "https://api.github.com";

      async function gh(endpoint, init) {
        const resp = await fetch(API_BASE + endpoint, {
          ...init,
          headers: {
            Accept: "application/vnd.github+json",
            Authorization: "Bearer " + TOKEN,
            "X-GitHub-Api-Version": "2022-11-28",
            ...(init?.headers ?? {}),
          },
        });
        if (!resp.ok) {
          const body = await resp.text();
          throw new Error("github " + resp.status + ": " + body.slice(0, 200));
        }
        return resp.json();
      }

      export async function searchRepositories(args) {
        const params = new URLSearchParams({ q: args.query });
        if (args.page) params.set("page", String(args.page));
        if (args.perPage) params.set("per_page", String(args.perPage));
        return gh("/search/repositories?" + params.toString());
      }
    `,
    dependencies: [
      {
        name: "@modelcontextprotocol/sdk",
        version: "1.5.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-01"),
      },
      {
        name: "zod",
        version: "3.23.8",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-01-15"),
      },
    ],
    connection_metadata: null,
  },
};
