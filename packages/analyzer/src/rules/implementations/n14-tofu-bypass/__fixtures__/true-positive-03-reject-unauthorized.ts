import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "// MCP fingerprint / known_hosts-style binding",
  "import { connect } from 'tls';",
  "export function link(host: string) {",
  "  return connect({ host, rejectUnauthorized: false });",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n14-tp3", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
