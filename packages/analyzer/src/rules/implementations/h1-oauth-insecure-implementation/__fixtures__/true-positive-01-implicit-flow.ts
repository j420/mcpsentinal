/**
 * H1 TP: OAuth implicit flow (response_type=token) — banned by RFC 9700 §2.1.2.
 *
 * This fixture is a source-code string that H1 will parse as TypeScript.
 */

import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = `
export function initiateAuth() {
  const params = {
    client_id: "abc",
    response_type: "token",
    redirect_uri: "https://app.example.com/callback",
  };
  return fetch("https://auth.example.com/authorize?" + new URLSearchParams(params));
}
`;

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-h1-tp1", name: "oauth-implicit", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
