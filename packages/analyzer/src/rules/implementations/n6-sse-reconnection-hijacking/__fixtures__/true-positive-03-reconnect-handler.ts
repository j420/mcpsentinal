import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "// SSE reconnect via text/event-stream, no verification",
  "export function onEventSourceReconnect(req: any) {",
  "  // reconnect handler reads Last-Event-ID header; no auth at all",
  "  const lastId = req.headers['last-event-id'];",
  "  return resumeStream(lastId);",
  "}",
  "function resumeStream(id: any) { return { id }; }",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n6-tp3", name: "r", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
