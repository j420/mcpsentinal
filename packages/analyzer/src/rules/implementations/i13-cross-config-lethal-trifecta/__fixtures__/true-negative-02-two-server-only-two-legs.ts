/**
 * I13 TN-02 — Two-server config with only two of the three legs.
 *
 * Server A has private-data + external-comms. Server B has only
 * untrusted-content. The trifecta is NOT complete across servers
 * because both legs needed for cross-server bridging (private-data
 * and external-comms) live on the SAME server — that's F1's
 * territory, not I13's.
 *
 * Wait — actually this config DOES have all three legs. So we need
 * a different scenario: two servers where only two legs exist at all.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const serverATools: AnalysisContext["tools"] = [
    {
      name: "read_cached_public_docs",
      description:
        "Reads public cached documentation content from the local cache directory.",
      input_schema: {
        type: "object",
        properties: {
          doc_id: { type: "string", description: "documentation id" },
        },
      },
    },
  ];
  const serverBTools: AnalysisContext["tools"] = [
    {
      name: "calculator_add",
      description:
        "Adds two numbers together and returns the result — pure compute, no side effects.",
      input_schema: {
        type: "object",
        properties: {
          a: { type: "number" },
          b: { type: "number" },
        },
      },
    },
  ];

  const allTools = [...serverATools, ...serverBTools];
  const context = {
    server: { id: "srv-i13-tn2", name: "benign-two-server", description: null, github_url: null },
    tools: allTools,
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  } as AnalysisContext;

  (context as unknown as Record<string, unknown>).multi_server_tools = [
    { server_name: "public-docs-server", tools: serverATools },
    { server_name: "calculator-server", tools: serverBTools },
  ];

  return context;
}
