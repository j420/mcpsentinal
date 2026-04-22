/**
 * H1 TP: ROPC grant (grant_type=password) — banned by RFC 9700 §2.4.
 */

import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = `
export async function login(username: string, password: string) {
  const body = new URLSearchParams({
    client_id: "abc",
    grant_type: "password",
    username,
    password,
  });
  const response = await fetch("https://auth.example.com/token", {
    method: "POST",
    body,
  });
  return response.json();
}
`;

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-h1-tp2", name: "oauth-ropc", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
