/**
 * Stresses H1 MCP OAuth 2.0 Insecure Implementation. This OAuth flow
 * uses PKCE (code_challenge/code_verifier) + state validation + short
 * access token TTL + refresh-token rotation. Fully aligned with
 * RFC 9700 / OAuth 2.1 best practice. H1 detects six attack shapes;
 * none appear here.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `import crypto from "node:crypto";

const REDIRECT_URI = "https://server.example.com/callback";

export function startAuth(): { authUrl: string; state: string; verifier: string } {
  const state = crypto.randomBytes(16).toString("base64url");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");
  const authUrl = new URL("https://auth.example.com/authorize");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  return { authUrl: authUrl.toString(), state, verifier };
}

export async function exchangeCode(code: string, verifier: string, storedState: string, returnedState: string) {
  if (storedState !== returnedState) {
    throw new Error("state mismatch");
  }
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
  });
  const r = await fetch("https://auth.example.com/token", { method: "POST", body });
  const json = (await r.json()) as { access_token: string; expires_in: number };
  // Short-lived access tokens, refresh rotation handled elsewhere.
  return { token: json.access_token, ttl: Math.min(json.expires_in, 900) };
}
`;

export const h1PkceOauthFixture: BenignFixture = {
  id: "edge-of-spec/h1-pkce-oauth",
  bucket: "edge-of-spec",
  why_benign:
    "H1 naive match on OAuth vocabulary. Flow uses PKCE + state validation " +
    "+ capped TTL + fixed redirect_uri + authorization_code grant — all H1 " +
    "attack shapes (implicit, ROPC, localStorage, user-controlled redirect) " +
    "are absent.",
  context: {
    server: {
      id: "edge/h1-pkce",
      name: "pkce-oauth-demo",
      description: "PKCE-compliant OAuth 2.1 client.",
      github_url: null,
    },
    tools: [
      {
        name: "start_auth",
        description: "Begin an OAuth 2.1 authorization-code flow with PKCE.",
        input_schema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
