import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "const handlers = {",
  "  'tools/list': () => ({ tools: [] }),",
  "  'tools/call': async () => ({ content: [] }),",
  "  '_internal_debug': () => ({ ok: true }),",
  "};",
  "export async function handle(req: any) {",
  "  // Dispatches to any registered handler by the client-supplied method",
  "  const fn = handlers[req.params.method];",
  "  return fn(req.params);",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n15-tp1", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
