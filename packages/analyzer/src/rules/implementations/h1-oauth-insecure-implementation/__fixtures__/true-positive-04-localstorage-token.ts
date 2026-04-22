/**
 * H1 TP: OAuth token stored in localStorage — banned by RFC 9700 §4.15.
 */

import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = `
export function handleTokenResponse(token: string) {
  localStorage.setItem("access_token", token);
  document.cookie = "authenticated=true";
}
`;

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-h1-tp4", name: "oauth-localstorage", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
