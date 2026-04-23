/**
 * Stresses F4 MCP Spec Non-Compliance. This server is MAXIMALLY
 * compliant: every tool has a description, every schema declares
 * `additionalProperties: false`, parameter descriptions are present,
 * annotations are declared. F4 should emit nothing; if it does the
 * rule is reading the spec wrong.
 */
import type { BenignFixture } from "../types.js";

export const f4StrictComplianceFixture: BenignFixture = {
  id: "edge-of-spec/f4-strict-compliance",
  bucket: "edge-of-spec",
  why_benign:
    "F4 Spec Compliance. Every tool has name+description, every schema is " +
    "`additionalProperties: false`, every param has a description and type. " +
    "Reference-perfect shape; F4 should emit nothing.",
  context: {
    server: {
      id: "edge/f4-strict",
      name: "strict-compliant",
      description: "Reference-shape MCP server.",
      github_url: null,
    },
    tools: [
      {
        name: "add",
        description: "Return the sum of two integers.",
        input_schema: {
          type: "object",
          properties: {
            a: { type: "integer", description: "First addend." },
            b: { type: "integer", description: "Second addend." },
          },
          required: ["a", "b"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, idempotentHint: true, destructiveHint: false },
      },
      {
        name: "multiply",
        description: "Return the product of two integers.",
        input_schema: {
          type: "object",
          properties: {
            a: { type: "integer", description: "First factor." },
            b: { type: "integer", description: "Second factor." },
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
