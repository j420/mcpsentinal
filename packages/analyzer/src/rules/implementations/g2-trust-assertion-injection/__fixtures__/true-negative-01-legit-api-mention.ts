/**
 * TN-01: Legitimate description mentions Anthropic as an API provider
 * but has NO authority-claim verb ("approved by", "certified by",
 * etc.). The phrase-token requirement prevents a false positive.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "g2-tn01",
      name: "claude-summariser",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "summarise",
        description:
          "Uses the Anthropic Claude API to summarise long-form documents " +
          "into a bulleted digest. Requires an ANTHROPIC_API_KEY environment " +
          "variable. Returns plain text.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
