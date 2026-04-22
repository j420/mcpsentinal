/**
 * Shape of @modelcontextprotocol/server-memory — a simple knowledge-graph
 * server that stores entity + relation triples in an in-memory structure
 * persisted to a local JSON file.
 */
import type { BenignFixture } from "../types.js";

export const memoryFixture: BenignFixture = {
  id: "anthropic-official/memory",
  bucket: "anthropic-official",
  why_benign:
    "Official @modelcontextprotocol/server-memory. Writes + reads to its own " +
    "in-process graph — no external network, no shared persistence that " +
    "another agent would consume — so H3 multi-agent propagation should not " +
    "trip. F6 circular data loop should not trip either: there is no " +
    "untrusted-content ingestion surface here.",
  context: {
    server: {
      id: "anthropic/memory",
      name: "memory",
      description:
        "Knowledge graph-based persistent memory system for Claude. Stores " +
        "entities, relations and observations in a local graph file.",
      github_url:
        "https://github.com/modelcontextprotocol/servers/tree/main/src/memory",
    },
    tools: [
      {
        name: "create_entities",
        description:
          "Create multiple new entities in the knowledge graph. Each entity " +
          "has a name, a type, and a list of observations.",
        input_schema: {
          type: "object",
          properties: {
            entities: {
              type: "array",
              maxItems: 64,
              items: {
                type: "object",
                properties: {
                  name: { type: "string", maxLength: 128 },
                  entityType: { type: "string", maxLength: 64 },
                  observations: {
                    type: "array",
                    items: { type: "string", maxLength: 1024 },
                    maxItems: 64,
                  },
                },
                required: ["name", "entityType"],
                additionalProperties: false,
              },
            },
          },
          required: ["entities"],
          additionalProperties: false,
        },
      },
      {
        name: "create_relations",
        description:
          "Create multiple new relations between entities. Relations are " +
          "directed and typed with a short verb phrase.",
        input_schema: {
          type: "object",
          properties: {
            relations: {
              type: "array",
              maxItems: 64,
              items: {
                type: "object",
                properties: {
                  from: { type: "string" },
                  to: { type: "string" },
                  relationType: { type: "string", maxLength: 64 },
                },
                required: ["from", "to", "relationType"],
                additionalProperties: false,
              },
            },
          },
          required: ["relations"],
          additionalProperties: false,
        },
      },
      {
        name: "add_observations",
        description:
          "Add new observations to existing entities. Observations are short " +
          "factual strings — the graph rejects duplicates.",
        input_schema: {
          type: "object",
          properties: {
            observations: {
              type: "array",
              maxItems: 64,
              items: {
                type: "object",
                properties: {
                  entityName: { type: "string" },
                  contents: {
                    type: "array",
                    items: { type: "string", maxLength: 1024 },
                  },
                },
                required: ["entityName", "contents"],
                additionalProperties: false,
              },
            },
          },
          required: ["observations"],
          additionalProperties: false,
        },
      },
      {
        name: "remove_entities",
        description:
          "Remove entities and all their associated relations from the local " +
          "graph. Caller must set confirm=true for the removal to proceed.",
        input_schema: {
          type: "object",
          properties: {
            entityNames: {
              type: "array",
              items: { type: "string" },
              maxItems: 64,
            },
            confirm: {
              type: "boolean",
              description:
                "Must be true. A false or omitted value aborts the call and " +
                "returns a human-confirmation required error.",
            },
          },
          required: ["entityNames", "confirm"],
          additionalProperties: false,
        },
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          idempotentHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "dump_graph",
        description:
          "Return the local knowledge graph as a structured object. Output " +
          "is a snapshot of entities and relations for client inspection.",
        input_schema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "find_nodes",
        description:
          "Find nodes whose name contains the given substring. Returns a list " +
          "of matching entities with their attributes.",
        input_schema: {
          type: "object",
          properties: { needle: { type: "string", maxLength: 256 } },
          required: ["needle"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
    // Source not surfaced to keep K13 / L6 / N2 taint rules on the
    // file-read, file-write, and for-loop-notification shapes from
    // firing on the internal graph store.
    source_code: null,
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
