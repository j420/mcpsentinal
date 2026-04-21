/**
 * TN-03: Edge-case documentation — JWT mentioned by STRUCTURE (header.payload.signature)
 * without a concrete long token.
 *
 * A9 v2 explicitly acknowledges in CHARTER.md that concrete long JWTs in
 * descriptions WILL fire (they are genuine base64url with high entropy and
 * often decode to readable JSON). This TN fixture covers the common case
 * where MCP docs describe JWT STRUCTURE rather than embedding an actual token.
 * It confirms the scanner doesn't hallucinate JWTs from words like "eyJhbGc"
 * when those words are themselves short.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "a9-tn03",
      name: "auth-gateway",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "exchange_token",
        description:
          "Exchanges an OAuth authorization code for a JWT. The returned JWT follows " +
          "the standard header.payload.signature format: the header begins with " +
          "'eyJhbGc' (that is, the base64url of {\"alg\":), the payload carries " +
          "standard claims (iss, sub, aud, exp, iat), and the signature is computed " +
          "with the configured algorithm. Do not log the token.",
        input_schema: {
          type: "object",
          properties: {
            code: {
              type: "string",
              description: "OAuth authorization code from the /authorize endpoint.",
            },
            redirect_uri: {
              type: "string",
              description: "The same redirect_uri used in the authorization request.",
            },
          },
          required: ["code", "redirect_uri"],
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
