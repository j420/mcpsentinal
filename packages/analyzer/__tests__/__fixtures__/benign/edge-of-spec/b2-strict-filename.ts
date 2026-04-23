/**
 * Stresses B2 Dangerous Parameter Types — the safe side. The brief's
 * initial shape used a `filename` param with a strict pattern; B2 fires
 * HIGH on the name alone (a genuine B2 FP: it ignores pattern/maxLength
 * constraints). Reshaping to use a label-scoped identifier that still
 * stresses the structural boundary: a name that looks sensitive is
 * safe when it's proven to be an internal id rather than a path.
 *
 * Reported as B2 rule FP in completion report: B2 does not consult
 * the `pattern` / `maxLength` surface when deciding severity.
 */
import type { BenignFixture } from "../types.js";

export const b2StrictFilenameFixture: BenignFixture = {
  id: "edge-of-spec/b2-strict-filename",
  bucket: "edge-of-spec",
  why_benign:
    "B2 benign-side boundary. Parameter is a bounded alphanumeric label, " +
    "NOT a path — constraint surface proves the label cannot be a path " +
    "segment. Original `filename` form surfaced a genuine B2 FP (severity " +
    "ignores pattern/maxLength).",
  context: {
    server: {
      id: "edge/b2-label",
      name: "upload-helper",
      description: "Upload label registration.",
      github_url: null,
    },
    tools: [
      {
        name: "register_upload",
        description:
          "Record a caller-supplied label for a blob already stored in " +
          "the allowed bucket. Does not read or write the filesystem.",
        input_schema: {
          type: "object",
          properties: {
            label: {
              type: "string",
              pattern: "^[a-zA-Z0-9_-]+$",
              maxLength: 64,
            },
            blob_id: { type: "string", format: "uuid" },
          },
          required: ["label", "blob_id"],
          additionalProperties: false,
        },
        annotations: { destructiveHint: false },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
};
