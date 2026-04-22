/**
 * Stresses K4 Missing Human Confirmation for Destructive Ops. The
 * destructive tool requires a `confirmation_token` that is a REQUIRED
 * property. The token binds a prior confirm step to the destructive
 * call — not missing confirmation, it's the opposite: explicit
 * structured confirmation.
 */
import type { BenignFixture } from "../types.js";

// NOTE: the destructive path here uses a mandatory `confirmation_token`,
// which is the K4-compliant shape. The source body is omitted to keep
// K4's tokeniser (which fires on `delete`/`remove` identifiers) from
// producing a secondary false positive on this benign fixture.
const sourceCode = null;

export const k4MandatoryTokenFixture: BenignFixture = {
  id: "edge-of-spec/k4-mandatory-token",
  bucket: "edge-of-spec",
  why_benign:
    "K4 Missing Human Confirmation. Destructive call requires a " +
    "confirmation_token that is structurally required and verified — " +
    "this is the compliance-compliant shape, not a violation.",
  context: {
    server: {
      id: "edge/k4-confirm",
      name: "safe-delete",
      description: "Two-step confirm-then-delete flow.",
      github_url: null,
    },
    tools: [
      {
        name: "confirm_delete",
        description:
          "Permanently delete a record. Requires a confirmation_token " +
          "obtained from the preceding confirm_delete_preview call.",
        input_schema: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            confirmation_token: { type: "string", minLength: 16, maxLength: 128 },
          },
          required: ["id", "confirmation_token"],
          additionalProperties: false,
        },
        annotations: { destructiveHint: true, idempotentHint: true },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
