/**
 * Shape of @modelcontextprotocol/server-postgres. Read-only SQL execution
 * server — connection string is provided as a CLI argument, queries go
 * through pg parameter binding, no DDL.
 */
import type { BenignFixture } from "../types.js";

export const postgresFixture: BenignFixture = {
  id: "anthropic-official/postgres",
  bucket: "anthropic-official",
  why_benign:
    "Official postgres server — queries are executed in a read-only " +
    "transaction via pg.Pool.query with literal SQL (not template " +
    "interpolation) and a connection string from CLI, not the MCP client. " +
    "No injection surface; no credentials collected over MCP.",
  context: {
    server: {
      id: "anthropic/postgres",
      name: "postgres",
      description:
        "A Model Context Protocol server that provides read-only access to " +
        "PostgreSQL databases for schema inspection and query execution.",
      github_url:
        "https://github.com/modelcontextprotocol/servers/tree/main/src/postgres",
    },
    tools: [
      {
        name: "postgres_read",
        description:
          "Run a read-only SQL statement against the connected PostgreSQL " +
          "database. The server wraps every call in a BEGIN TRANSACTION READ " +
          "ONLY / ROLLBACK cycle.",
        input_schema: {
          type: "object",
          properties: { statement: { type: "string", maxLength: 16384 } },
          required: ["statement"],
          additionalProperties: false,
        },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: true,
        },
      },
    ],
    // Source dropped — postgres fixture focuses on the MCP-surface
    // (single read-only `query` tool) rather than the pg connection glue.
    source_code: null,
    dependencies: [
      {
        name: "@modelcontextprotocol/sdk",
        version: "1.5.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-01"),
      },
      {
        name: "pg",
        version: "8.11.3",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-01-25"),
      },
    ],
    connection_metadata: null,
  },
};
