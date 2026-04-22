/**
 * Shape of the Neon MCP server — serverless Postgres provisioning and
 * query-runner. Distinct from anthropic-official/postgres (that one is
 * generic libpq; Neon manages projects and branches).
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const neonPostgresFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/neon",
  name: "neon",
  why:
    "Neon MCP. Stresses B2 dangerous-parameter-types negative (uses " +
    "statement_text, not sql/query), F5 namespace-squatting negative " +
    "(Neon upstream brand), and I11 over-privileged-root negative " +
    "(no filesystem roots declared).",
  description:
    "Neon Serverless Postgres MCP — manage projects, run branches, " +
    "and execute parameterised statements scoped to the API key.",
  github_url: "https://github.com/neondatabase/mcp-server-neon",
  tools: [
    {
      name: "list_projects",
      description:
        "List Neon projects accessible to the authenticated API key.",
      input_schema: {
        type: "object",
        properties: {
          cursor: { type: "string", maxLength: 256 },
        },
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "branch_new",
      description:
        "Make a copy-on-write branch of a Neon project. Safe, cheap, " +
        "and does not affect the source branch.",
      input_schema: {
        type: "object",
        properties: {
          project_id: { type: "string", pattern: "^[a-z0-9-]{8,64}$" },
          branch_name: { type: "string", maxLength: 64 },
          parent_id: { type: "string", maxLength: 64 },
        },
        required: ["project_id", "branch_name"],
        additionalProperties: false,
      },
    },
    {
      name: "run_statement",
      description:
        "Execute a parameterised statement on a project branch. " +
        "Parameters are bound via the server driver; values never " +
        "interpolate into the statement text.",
      input_schema: {
        type: "object",
        properties: {
          project_id: { type: "string", maxLength: 64 },
          branch_id: { type: "string", maxLength: 64 },
          statement_text: { type: "string", maxLength: 16384 },
          params: {
            type: "array",
            items: { type: ["string", "number", "boolean", "null"] },
            maxItems: 64,
          },
        },
        required: ["project_id", "branch_id", "statement_text"],
        additionalProperties: false,
      },
    },
  ],
});
