/**
 * Supabase MCP server — inspect and manage Supabase projects.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const supabaseFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/supabase",
  name: "supabase",
  why:
    "Supabase MCP. Stresses B7 dangerous-default-values negative (no " +
    "recursive/allow_overwrite defaults), and F5 squatting negative.",
  description:
    "Supabase MCP server — list projects, read Postgres via the " +
    "parameterised REST interface, and manage storage buckets.",
  github_url: "https://github.com/supabase-community/supabase-mcp",
  tools: [
    {
      name: "list_projects",
      description: "List Supabase projects for the access token.",
      input_schema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "select_rows",
      description:
        "Run a parameterised PostgREST select against a table. Filter " +
        "and order parameters are passed as structured arguments.",
      input_schema: {
        type: "object",
        properties: {
          project_ref: { type: "string", pattern: "^[a-z]{16,20}$" },
          table_name: { type: "string", pattern: "^[a-zA-Z_][a-zA-Z0-9_]*$" },
          columns: {
            type: "array",
            items: { type: "string", pattern: "^[a-zA-Z_][a-zA-Z0-9_]*$" },
            maxItems: 64,
          },
          limit: { type: "integer", minimum: 1, maximum: 1000 },
        },
        required: ["project_ref", "table_name"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
});
