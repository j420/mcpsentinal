/**
 * H2 TN-02 — Legitimate initialize metadata.
 *
 * server.name is an identifier; server_version is semver; instructions
 * is short operational guidance. No special tokens, no Unicode
 * control characters, no base64 runs, no directive phrases.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "h2-tn02",
      name: "mcp-filesystem",
      description: null,
      github_url: null,
    },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    initialize_metadata: {
      server_version: "2.1.0",
      server_instructions:
        "Read-only filesystem server. Use the search tool before fetch " +
        "to locate candidate files.",
    },
  };
}
