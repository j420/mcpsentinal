/**
 * H1 TP: redirect_uri sourced from user input — enables OAuth code injection.
 */

import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = `
export function buildAuthUrl(req: any) {
  const params = new URLSearchParams({
    client_id: "abc",
    response_type: "code",
    redirect_uri: req.query.return_to,
  });
  return "https://auth.example.com/authorize?" + params.toString();
}
`;

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-h1-tp3", name: "oauth-redirect-taint", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
