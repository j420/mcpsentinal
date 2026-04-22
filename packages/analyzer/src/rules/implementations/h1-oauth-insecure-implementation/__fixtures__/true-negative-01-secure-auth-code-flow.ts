/**
 * H1 TN: RFC-9700-compliant authorisation-code flow with PKCE, state, and
 * static redirect_uri.
 */

import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = `
const REGISTERED_REDIRECT = "https://app.example.com/callback";

export function initiateAuth(sessionStore: Map<string, string>) {
  const stateValue = crypto.randomUUID();
  sessionStore.set("oauth:state", stateValue);
  const params = new URLSearchParams({
    client_id: "abc",
    response_type: "code",
    redirect_uri: REGISTERED_REDIRECT,
    state: stateValue,
  });
  return "https://auth.example.com/authorize?" + params.toString();
}

export function handleCallback(req: any, sessionStore: Map<string, string>) {
  const receivedState = req.query.state;
  const expectedState = sessionStore.get("oauth:state");
  if (receivedState !== expectedState) {
    throw new Error("state mismatch");
  }
  const code = req.query.code;
  return exchangeCode(code);
}

async function exchangeCode(code: string) {
  const body = new URLSearchParams({
    client_id: "abc",
    grant_type: "authorization_code",
    code,
    redirect_uri: REGISTERED_REDIRECT,
  });
  const response = await fetch("https://auth.example.com/token", { method: "POST", body });
  return response.json();
}
`;

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-h1-tn1", name: "oauth-secure", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
