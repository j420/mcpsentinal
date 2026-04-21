/**
 * A6 TN #1 — Plain ASCII tool name and description.
 *
 * No homoglyph can exist in a pure-ASCII identifier. The rule must not fire.
 */

import type { AnalysisContext } from "../../../../engine.js";

export const fixture: AnalysisContext = {
  server: {
    id: "tn-01",
    name: "files",
    description: "File-system tools",
    github_url: null,
  },
  tools: [
    {
      name: "read_file",
      description: "Read the contents of a file at the given path and return it as text.",
      input_schema: null,
    },
    {
      name: "write_file",
      description: "Write text content to a file at the given path.",
      input_schema: null,
    },
  ],
  source_code: null,
  dependencies: [],
  connection_metadata: null,
};

export const expectation = {
  rule_id: "A6",
  min_findings: 0,
  max_findings: 0,
};
