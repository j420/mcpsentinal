/**
 * A7 TN #2 — Legitimate emoji ZWJ sequence (woman-technologist).
 *
 * U+1F469 (woman) + U+200D (ZWJ) + U+1F4BB (personal computer) = 👩‍💻.
 * The ZWJ is flanked on both sides by emoji codepoints — the Unicode-blessed
 * ligature use case. gather.ts must suppress this and the rule MUST NOT fire.
 */

import type { AnalysisContext } from "../../../../engine.js";

export const fixture: AnalysisContext = {
  server: {
    id: "tn-02",
    name: "friendly",
    description: null,
    github_url: null,
  },
  tools: [
    {
      name: "greet",
      // "Say hi to the team 👩‍💻" — ZWJ between emoji codepoints
      description: "Say hi to the team 👩‍💻 — prints a friendly greeting.",
      input_schema: null,
    },
  ],
  source_code: null,
  dependencies: [],
  connection_metadata: null,
};

export const expectation = {
  rule_id: "A7",
  min_findings: 0,
  max_findings: 0,
  rationale:
    "ZWJ between emoji codepoints is a legitimate ligature; the emoji-suppression rule must skip it.",
};
