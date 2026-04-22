/**
 * Stresses B7 Dangerous Default Parameter Values. A default of `true`
 * on a parameter named `verbose` is a non-security default: verbose
 * logging is not a privilege escalation. B7 must distinguish security
 * defaults (recursive, allow_overwrite) from cosmetic ones (verbose).
 */
import type { BenignFixture } from "../types.js";

export const b7VerboseDefaultFixture: BenignFixture = {
  id: "edge-of-spec/b7-verbose-default",
  bucket: "edge-of-spec",
  why_benign:
    "B7 naive match on `default: true` fires. Structural B7 checks that " +
    "the parameter name carries security semantics — `verbose` does not.",
  context: {
    server: {
      id: "edge/b7-verbose",
      name: "diff-viewer",
      description: "Structured diff viewer.",
      github_url: null,
    },
    tools: [
      {
        name: "render_diff",
        description:
          "Render a unified diff between two blobs. `verbose` controls " +
          "whether whitespace-only changes are included in the output.",
        input_schema: {
          type: "object",
          properties: {
            blob_a: { type: "string", format: "uuid" },
            blob_b: { type: "string", format: "uuid" },
            verbose: { type: "boolean", default: true },
          },
          required: ["blob_a", "blob_b"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
};
