import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "// resources/subscribe mounted",
  "export async function subscribe(uri: string) { return { uri }; }",
  "export async function onChange(uri: string, content: string) {",
  "  // Bare sendUpdate — no hash, no verify, no signature",
  "  await sendUpdate({ uri, content });",
  "}",
  "async function sendUpdate(_: any) {}",
  "// resources/subscribe handler registered earlier",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n12-tp3", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
