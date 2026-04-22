/**
 * TN-02: A documentation-rich server where every tool has a legitimate
 * ~1200-byte description. Lengths are uniform — no peer z-score outlier.
 * Descriptions document multiple parameters proportionally (ratio under
 * the threshold). No tail imperative density, no repetition signature.
 *
 * G4 must NOT fire on this fixture.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const writeup =
    "This tool queries the reporting store and returns a structured result set. " +
    "Parameters: `query` — the search expression (supports AND/OR/NOT operators " +
    "and quoted phrases); `limit` — maximum rows returned, 1..1000; `offset` — " +
    "zero-based offset into the result set; `fields` — optional comma-separated " +
    "projection of columns to include. Constraints: queries that would return " +
    "more than one million candidate rows are rejected with a structured error. " +
    "Rate-limiting applies at the per-caller level; when throttled, the response " +
    "carries a Retry-After value in the structured output. Authorization checks " +
    "are performed before the store is queried; unauthorised callers receive a " +
    "minimal error envelope with no data leakage. All data returned respects the " +
    "caller's org scope; cross-tenant leakage is impossible by construction. For " +
    "operational notes see the runbook linked from the repository README.";
  const longTools = [
    "report_query",
    "report_summary",
    "report_export",
    "report_schedule",
    "report_inspect",
    "report_metadata",
  ];
  const tools = longTools.map((name) => ({
    name,
    description: writeup,
    input_schema: {
      type: "object",
      properties: {
        query: { type: "string" },
        limit: { type: "integer" },
        offset: { type: "integer" },
        fields: { type: "string" },
        format: { type: "string" },
        org_scope: { type: "string" },
      },
    },
  }));

  return {
    server: {
      id: "g4-tn02",
      name: "tn02-documentation-rich",
      description: null,
      github_url: null,
    },
    tools,
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
