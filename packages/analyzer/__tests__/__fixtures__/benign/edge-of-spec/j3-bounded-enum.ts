/**
 * Stresses J3 Full Schema Poisoning. The schema declares an enum of
 * three fixed values — no shell metacharacters, no template interpolation,
 * no default holding executable tokens. J3 extends beyond descriptions
 * to enum/title/const/default fields; the boundary is "is the enum
 * value a format label or a payload?". Here, the values are format
 * labels.
 */
import type { BenignFixture } from "../types.js";

export const j3BoundedEnumFixture: BenignFixture = {
  id: "edge-of-spec/j3-bounded-enum",
  bucket: "edge-of-spec",
  why_benign:
    "J3 naive scan of enum values. The enum is ['csv','json','xml'] — " +
    "format labels, not shell or injection payloads.",
  context: {
    server: {
      id: "edge/j3-enum",
      name: "export-formats",
      description: "Export data in a fixed set of formats.",
      github_url: null,
    },
    tools: [
      {
        name: "export_report",
        description:
          "Export a report in one of the supported formats. The chosen " +
          "format must be one of the declared enum values.",
        input_schema: {
          type: "object",
          properties: {
            report_id: { type: "string", format: "uuid" },
            format: { type: "string", enum: ["csv", "json", "xml"] },
          },
          required: ["report_id", "format"],
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
