/**
 * Stresses J6 Tool Preference Manipulation. The description is a plain,
 * neutral factual statement about what the tool does — no "always use
 * this first", no "replaces the old X", no "do not use any other tool".
 * J6 flags linguistic markers of preference hijack; absence of those
 * markers means the tool is benign.
 */
import type { BenignFixture } from "../types.js";

export const j6NeutralDescriptionFixture: BenignFixture = {
  id: "edge-of-spec/j6-neutral-description",
  bucket: "edge-of-spec",
  why_benign:
    "J6 linguistic scan for preference-manipulation markers. Description " +
    "is neutral and factual — no 'always', no 'replaces', no exclusion.",
  context: {
    server: {
      id: "edge/j6-neutral",
      name: "gh-issues",
      description: "GitHub issue access.",
      github_url: null,
    },
    tools: [
      {
        name: "fetch_issues",
        description: "This tool fetches GitHub issues for a repository.",
        input_schema: {
          type: "object",
          properties: {
            owner: { type: "string", maxLength: 64 },
            repo: { type: "string", maxLength: 64 },
          },
          required: ["owner", "repo"],
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
