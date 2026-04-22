/**
 * TN-02: Documentation page explains JSON-RPC protocol for
 * educational purposes. The fence tokens ("documentation",
 * "educational", "explains") demote any catalogue matches below
 * the confidence floor.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "g3-tn02",
      name: "protocol-docs",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "fetch_docs",
        description:
          "Educational documentation tool. Explains the JSON-RPC 2 0 protocol " +
          "and the MCP protocol tools/call method for readers learning about " +
          "agent integrations. Returns plain-text educational content about " +
          "how protocol messages work.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
