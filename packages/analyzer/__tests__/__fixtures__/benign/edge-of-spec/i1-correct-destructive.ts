/**
 * Stresses I1 Annotation Deception. A tool named `delete_document`
 * with `destructiveHint: true` — correctly annotated. I1 fires when
 * annotation says one thing and behaviour says another; here the
 * annotation matches the behaviour, so I1 should not trigger.
 */
import type { BenignFixture } from "../types.js";

export const i1CorrectDestructiveFixture: BenignFixture = {
  id: "edge-of-spec/i1-correct-destructive",
  bucket: "edge-of-spec",
  why_benign:
    "I1 Annotation Deception. The tool is destructive AND has " +
    "destructiveHint: true — honest annotation, not deception.",
  context: {
    server: {
      id: "edge/i1-correct",
      name: "document-store",
      description: "Document CRUD.",
      github_url: null,
    },
    tools: [
      {
        name: "read_document",
        description: "Return document contents.",
        input_schema: {
          type: "object",
          properties: { id: { type: "string", format: "uuid" } },
          required: ["id"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
      {
        name: "delete_document",
        description:
          "Remove a document by id. Requires a confirmation_token from " +
          "the preceding preview step.",
        input_schema: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            confirmation_token: { type: "string", minLength: 16, maxLength: 128 },
          },
          required: ["id", "confirmation_token"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
};
