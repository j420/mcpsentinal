import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "// No TOFU / fingerprint / known_hosts anywhere",
  "export function add(a: number, b: number) { return a + b; }",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n14-tn1", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
