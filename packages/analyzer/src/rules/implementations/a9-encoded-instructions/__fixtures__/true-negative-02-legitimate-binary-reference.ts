/**
 * TN-02: Description that mentions a SHORT base64 value as an illustrative
 * example. The block is <32 chars so it stays below the A9 threshold.
 *
 * Documents the contract: A9 v2 deliberately does not fire on short
 * base64 illustrative values. v1's entropy-only approach would have
 * probabilistically flagged these; v2 trades that noise for reviewer
 * reproducibility. The TN-02 fixture preserves this contract.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "a9-tn02",
      name: "fingerprint-api",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "hash_content",
        description:
          "Computes a content hash. Example response: { hash: 'Zm9vYmFyYmF6Cg==' } " +
          "where the value is the base64 of the canonical form.",
        input_schema: {
          type: "object",
          properties: {
            content: {
              type: "string",
              description:
                "Raw content string to hash. Response format follows RFC 4648 section 4.",
            },
          },
          required: ["content"],
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
