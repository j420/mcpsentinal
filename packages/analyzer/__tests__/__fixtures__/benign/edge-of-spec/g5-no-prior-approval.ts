/**
 * Stresses G5 Capability Escalation via Prior Approval. The tool is a
 * fresh, self-contained capability with no cross-reference to prior
 * approvals, no "same access as" language, no session-state claims.
 * This is the neutral baseline that G5 must leave alone.
 */
import type { BenignFixture } from "../types.js";

export const g5NoPriorApprovalFixture: BenignFixture = {
  id: "edge-of-spec/g5-no-prior-approval",
  bucket: "edge-of-spec",
  why_benign:
    "G5 Capability Escalation via Prior Approval. Description does NOT " +
    "reference prior permissions, prior tools, or session state.",
  context: {
    server: {
      id: "edge/g5-standalone",
      name: "standalone-calculator",
      description: "Self-contained calculator.",
      github_url: null,
    },
    tools: [
      {
        name: "add",
        description:
          "Return the sum of two integers. Each invocation is independent.",
        input_schema: {
          type: "object",
          properties: {
            a: { type: "integer" },
            b: { type: "integer" },
          },
          required: ["a", "b"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, idempotentHint: true, destructiveHint: false },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
};
