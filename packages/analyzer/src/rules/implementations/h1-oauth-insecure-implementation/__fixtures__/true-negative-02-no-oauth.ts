/**
 * H1 TN: source code with no OAuth patterns at all.
 */

import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = `
export function add(a: number, b: number): number {
  return a + b;
}
`;

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-h1-tn2", name: "no-oauth", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
