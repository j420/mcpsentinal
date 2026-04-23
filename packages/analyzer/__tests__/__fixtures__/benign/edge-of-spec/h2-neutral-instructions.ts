/**
 * Stresses H2 Prompt Injection in MCP Initialize Response Fields.
 * `initialize_metadata.server_instructions` is a short, neutral,
 * descriptive sentence. No role framing, no imperative, no authority
 * claim, no unicode, no encoding. H2's linguistic scoring should not
 * fire on plain descriptive prose.
 */
import type { BenignFixture } from "../types.js";

export const h2NeutralInstructionsFixture: BenignFixture = {
  id: "edge-of-spec/h2-neutral-instructions",
  bucket: "edge-of-spec",
  why_benign:
    "H2 naive field scan. Instructions field is a single neutral sentence " +
    "describing what the server provides — no imperative, no role framing.",
  context: {
    server: {
      id: "edge/h2-neutral",
      name: "uuid-mint",
      description: "UUID mint.",
      github_url: null,
    },
    tools: [
      {
        name: "mint_uuid",
        description: "Generate a new v4 UUID.",
        input_schema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, idempotentHint: false },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    initialize_metadata: {
      server_version: "1.0.3",
      server_instructions:
        "This server provides a single tool for minting v4 UUIDs.",
    },
  },
};
