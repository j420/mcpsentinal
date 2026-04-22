import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "// Uses net.Socket and text/event-stream — Streamable HTTP",
  "import * as net from 'net';",
  "export function write(socket: net.Socket, payload: string) {",
  "  // Hand-rolled chunked terminator — desync-prone",
  "  socket.write(`${payload.length.toString(16)}\\r\\n${payload}\\r\\n0\\r\\n\\r\\n`);",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n13-tp2", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
