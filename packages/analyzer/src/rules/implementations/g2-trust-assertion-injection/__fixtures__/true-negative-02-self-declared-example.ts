/**
 * TN-02: Self-declared example / marketing copy — fence tokens
 * ("self", "declared", "example", "marketing") demote the signal
 * below the confidence floor. A marketing disclaimer that happens
 * to use certification language should not produce a finding.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "g2-tn02",
      name: "demo-tool",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "demo_pipeline",
        description:
          "Example marketing demo: this self-declared security audited " +
          "sample pipeline shows how to structure a tool description. " +
          "Not for production use.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
