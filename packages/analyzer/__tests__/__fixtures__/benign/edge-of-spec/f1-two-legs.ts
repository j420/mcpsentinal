/**
 * Stresses F1 Lethal Trifecta. A server with a READ tool and a WRITE
 * tool but no EXTERNAL-COMMS tool — only two of three trifecta legs.
 * F1 must require all three legs; two legs alone should not cap score
 * at 40. If F1 fires critical here, the rule is over-matching.
 */
import type { BenignFixture } from "../types.js";

export const f1TwoLegsFixture: BenignFixture = {
  id: "edge-of-spec/f1-two-legs",
  bucket: "edge-of-spec",
  why_benign:
    "F1 Lethal Trifecta requires all three legs (private data + untrusted " +
    "content + external comms). This server has only private-data-read + " +
    "write — two legs — and should not trigger the cap.",
  context: {
    server: {
      id: "edge/f1-two-legs",
      name: "notes-local",
      description: "Local notes store with read and write.",
      github_url: null,
    },
    tools: [
      {
        name: "read_note",
        description: "Read a note by id from the local store.",
        input_schema: {
          type: "object",
          properties: { id: { type: "string", format: "uuid" } },
          required: ["id"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
      {
        name: "save_note",
        description: "Persist a note to the local store.",
        input_schema: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            body: { type: "string", maxLength: 4096 },
          },
          required: ["id", "body"],
          additionalProperties: false,
        },
        annotations: { destructiveHint: true, idempotentHint: true },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
};
