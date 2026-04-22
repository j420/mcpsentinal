/**
 * I1 negative — readOnlyHint: true on a tool whose parameter shape is
 * a narrowing filter, NOT a destructive operation. Description avoids
 * the substring "write".
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const i1ReadOnlyQueryFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/i1-read-only-with-filter-param",
  name: "report-filter",
  why:
    "readOnlyHint: true is accurate — the tool only reads, and its " +
    "filter_text parameter is a narrowing term. Description is free " +
    "of destructive verbs. Stresses I1 annotation-deception negative.",
  description:
    "Returns the subset of reports whose metadata matches the " +
    "supplied filter text. Performs no mutations.",
  tools: [
    {
      name: "filter_reports",
      description:
        "Return reports whose metadata matches the supplied filter " +
        "text. Purely a narrowing operation.",
      input_schema: {
        type: "object",
        properties: {
          filter_text: { type: "string", maxLength: 256 },
          limit: { type: "integer", minimum: 1, maximum: 100 },
        },
        required: ["filter_text"],
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
  ],
  source_code: `
    const ALL_REPORTS = [];

    export async function filterReports(filterText, limit) {
      const needle = String(filterText).toLowerCase();
      const out = [];
      for (const r of ALL_REPORTS) {
        if (r.title.toLowerCase().includes(needle)) out.push(r);
        if (out.length >= (limit ?? 25)) break;
      }
      return out;
    }
  `,
});
