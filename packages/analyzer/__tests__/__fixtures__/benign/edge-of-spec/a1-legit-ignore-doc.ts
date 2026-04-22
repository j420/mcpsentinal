/**
 * Stresses A1 Prompt Injection in Tool Description. A naive regex on
 * "ignore" fires here because the word appears in legitimate API
 * documentation. The structural analyser requires imperative role/
 * instruction framing — a descriptive sentence about what the tool
 * does to empty strings does not match.
 */
import type { BenignFixture } from "../types.js";

export const a1LegitIgnoreDocFixture: BenignFixture = {
  id: "edge-of-spec/a1-legit-ignore-doc",
  bucket: "edge-of-spec",
  why_benign:
    "Trips A1 naive 'ignore' keyword match, passes structural linguistic scoring: " +
    "the sentence is descriptive API documentation, not an imperative role-switch.",
  context: {
    server: {
      id: "edge/a1-ignore-doc",
      name: "text-normaliser",
      description: "String normalisation helper with Unicode support.",
      github_url: null,
    },
    tools: [
      {
        name: "normalise_whitespace",
        description:
          "Collapse runs of whitespace. The tool will ignore empty strings " +
          "and return the input unchanged. Tabs and newlines are treated " +
          "equivalently to spaces.",
        input_schema: {
          type: "object",
          properties: { text: { type: "string", maxLength: 65536 } },
          required: ["text"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
};
