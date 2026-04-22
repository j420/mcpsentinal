/**
 * I11 negative — no roots at all declared. The "over-privileged root"
 * rule only fires when the server declares a filesystem root and that
 * root is sensitive; a server with no roots is trivially not over-
 * privileged.
 */
import type { BenignFixture } from "../types.js";

export const i11ProjectRootFixture: BenignFixture = {
  id: "canonical-non-mcp/i11-no-roots-declared",
  bucket: "canonical-non-mcp",
  why_benign:
    "Server declares NO roots, so I11 has nothing to flag. Stresses " +
    "I11 over-privileged-root negative via the absence branch — the " +
    "rule must not fire when no roots are declared.",
  context: {
    server: {
      id: "rootless-helper",
      name: "rootless-helper",
      description:
        "Project-scoped helper that declares no filesystem roots " +
        "— all state lives in memory.",
      github_url: "https://github.com/sample/rootless-helper",
    },
    tools: [
      {
        name: "list_in_memory_items",
        description: "List items currently in the in-memory store.",
        input_schema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, idempotentHint: true },
      },
    ],
    source_code: null,
    dependencies: [
      {
        name: "@modelcontextprotocol/sdk",
        version: "1.5.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-03-01"),
      },
    ],
    connection_metadata: null,
  },
};
