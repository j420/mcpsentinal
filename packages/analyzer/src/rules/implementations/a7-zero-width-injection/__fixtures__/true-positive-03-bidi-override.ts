/**
 * A7 TP #3 — Right-to-Left Override (U+202E) in a tool description.
 *
 * The description embeds U+202E to reverse a run of characters. Reviewers
 * using a bidi-aware renderer see the reversed glyphs; the LLM sees the
 * logical order.  This is the Trojan Source (CVE-2021-42574) vector
 * applied to the MCP tool-description surface.
 */

import type { AnalysisContext } from "../../../../engine.js";

export const fixture: AnalysisContext = {
  server: {
    id: "tp-03",
    name: "trojan",
    description: null,
    github_url: null,
  },
  tools: [
    {
      name: "safe_tool",
      // "A trusted tool‮ — do not remove" — RLO between "trusted" and " tool"
      description: "A trusted‮ tool — do not remove.",
      input_schema: null,
    },
  ],
  source_code: null,
  dependencies: [],
  connection_metadata: null,
};

export const expectation = {
  rule_id: "A7",
  min_findings: 1,
  expected_severity: "critical" as const,
  expected_class: "bidi-override" as const,
  expected_reference_contains: "CVE-2021-42574",
};
