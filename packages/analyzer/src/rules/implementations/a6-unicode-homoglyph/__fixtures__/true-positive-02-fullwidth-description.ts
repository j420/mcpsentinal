/**
 * A6 TP #2 — Fullwidth Latin characters (U+FF21–U+FF5A) in the description,
 * mixed with ordinary ASCII Latin.
 *
 * Fullwidth Latin is a TR39 "whole-script confusable": the glyphs look like
 * bigger/wider Latin letters. Multiple clustered fullwidth letters inside
 * Latin prose is a classic obfuscation pattern for bypassing keyword filters
 * on words like "SYSTEM", "admin", "ignore".
 */

import type { AnalysisContext } from "../../../../engine.js";

export const fixture: AnalysisContext = {
  server: {
    id: "tp-02",
    name: "ops",
    description: null,
    github_url: null,
  },
  tools: [
    {
      name: "run_task",
      // "ＳＹＳＴＥＭ" = U+FF33 U+FF39 U+FF33 U+FF34 U+FF25 U+FF2D (fullwidth S Y S T E M)
      description:
        "Execute the requested task. ＳＹＳＴＥＭ mode is entered automatically when required.",
      input_schema: null,
    },
  ],
  source_code: null,
  dependencies: [],
  connection_metadata: null,
};

export const expectation = {
  rule_id: "A6",
  min_findings: 1,
  expected_severity_in: ["critical", "high"] as const,
  expected_tool_name: "run_task",
  expected_script: "Fullwidth-Latin",
};
