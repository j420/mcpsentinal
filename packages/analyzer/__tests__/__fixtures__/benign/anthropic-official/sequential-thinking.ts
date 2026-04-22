/**
 * Shape of @modelcontextprotocol/server-sequential-thinking. A pure
 * reasoning tool — no side effects at all, just structured thought
 * capture that returns the same JSON back.
 */
import type { BenignFixture } from "../types.js";

export const sequentialThinkingFixture: BenignFixture = {
  id: "anthropic-official/sequential-thinking",
  bucket: "anthropic-official",
  why_benign:
    "Official sequential-thinking server — pure reasoning scaffold with " +
    "zero side effects and zero external communication. Stresses F1 lethal " +
    "trifecta negative: no data + no untrusted content + no egress = no " +
    "finding possible.",
  context: {
    server: {
      id: "anthropic/sequential-thinking",
      name: "sequential-thinking",
      description:
        "MCP server for dynamic and reflective problem solving through " +
        "structured thoughts. The server records a thought sequence and " +
        "returns it without side effects.",
      github_url:
        "https://github.com/modelcontextprotocol/servers/tree/main/src/sequentialthinking",
    },
    tools: [
      {
        name: "sequentialthinking",
        description:
          "A detailed tool for dynamic and reflective problem solving " +
          "through a chain of thoughts. Each invocation records one thought " +
          "and optionally revises a previous one.",
        input_schema: {
          type: "object",
          properties: {
            thought: { type: "string", maxLength: 4096 },
            thoughtNumber: { type: "integer", minimum: 1, maximum: 100 },
            totalThoughts: { type: "integer", minimum: 1, maximum: 100 },
            nextThoughtNeeded: { type: "boolean" },
            isRevision: { type: "boolean" },
            revisesThought: { type: "integer", minimum: 1, maximum: 100 },
          },
          required: ["thought", "thoughtNumber", "totalThoughts", "nextThoughtNeeded"],
          additionalProperties: false,
        },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: false,
          openWorldHint: false,
        },
      },
    ],
    source_code: `
      // Pure in-memory thought log, reset per server lifecycle.
      const thoughts = [];

      export function record(args) {
        thoughts.push({
          number: args.thoughtNumber,
          total: args.totalThoughts,
          text: args.thought,
          revises: args.revisesThought ?? null,
          ts: Date.now(),
        });
        return {
          count: thoughts.length,
          next: args.nextThoughtNeeded,
        };
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
    ],
    connection_metadata: null,
  },
};
