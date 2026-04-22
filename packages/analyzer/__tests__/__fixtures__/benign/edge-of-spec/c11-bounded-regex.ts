/**
 * Stresses C11 ReDoS Vulnerability. A regex built from a literal
 * character class `/^[a-z]+$/` is bounded, non-alternating, and not
 * constructed from user input — no catastrophic-backtracking shape.
 * Naive "any regex with + inside" matchers false-positive here.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `/** Validate that a tag name is all-lowercase ASCII letters. */
export function isLowercaseAscii(tag: string): boolean {
  return /^[a-z]+$/.test(tag);
}
`;

export const c11BoundedRegexFixture: BenignFixture = {
  id: "edge-of-spec/c11-bounded-regex",
  bucket: "edge-of-spec",
  why_benign:
    "C11 naive match on `+`. Regex is a single bounded character class with " +
    "no alternation and no user-constructed RegExp — not catastrophic.",
  context: {
    server: {
      id: "edge/c11-regex",
      name: "tag-validator",
      description: "Tag name validation.",
      github_url: null,
    },
    tools: [
      {
        name: "is_lowercase_ascii",
        description: "Return true if the tag is all lowercase ASCII letters.",
        input_schema: {
          type: "object",
          properties: { tag: { type: "string", maxLength: 64 } },
          required: ["tag"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
