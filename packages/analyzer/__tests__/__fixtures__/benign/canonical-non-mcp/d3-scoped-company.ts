/**
 * D3 negative — scoped package name that is NOT similar to any known
 * vendor namespace. Typosquatting rule should not trigger.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture, FRESH } from "./_helpers.js";

export const d3ScopedCompanyFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/d3-scoped-company-namespace",
  name: "internal-reports",
  why:
    "Scoped package @acme-widgets/reports — dissimilar from Anthropic, " +
    "OpenAI, Google, etc. Stresses D3 typosquatting-risk negative and " +
    "F5 namespace-squatting negative.",
  description:
    "Reads generated reports from a company's internal storage bucket.",
  tools: [
    {
      name: "fetch_report",
      description: "Fetch one report by id from the internal bucket.",
      input_schema: {
        type: "object",
        properties: {
          report_id: { type: "string", pattern: "^RPT-[0-9]{6}$" },
        },
        required: ["report_id"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    import { getReport } from "@acme-widgets/reports";

    export async function fetchReport(reportId) {
      return getReport(reportId);
    }
  `,
  extraDeps: [
    {
      name: "@acme-widgets/reports",
      version: "2.4.0",
      has_known_cve: false,
      cve_ids: [],
      last_updated: FRESH,
    },
  ],
});
