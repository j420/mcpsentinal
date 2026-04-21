/**
 * A7 TN #1 — Plain ASCII name and description, no invisible codepoints.
 * The rule MUST NOT fire.
 */

import type { AnalysisContext } from "../../../../engine.js";

export const fixture: AnalysisContext = {
  server: {
    id: "tn-01",
    name: "files",
    description: "File-system utilities",
    github_url: null,
  },
  tools: [
    {
      name: "read_file",
      description: "Read the contents of a file at the given path and return it as text.",
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
};
