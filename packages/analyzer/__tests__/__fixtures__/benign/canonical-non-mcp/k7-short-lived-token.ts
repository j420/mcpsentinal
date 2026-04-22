/**
 * K7 negative — short-lived token, 15 minute expiry, rotated.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const k7ShortLivedTokenFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/k7-short-lived-token",
  name: "minted-sessions",
  why:
    "Session token has a 15-minute expiry and is rotated on every " +
    "issue. Stresses K7 long-lived-tokens-without-rotation negative.",
  description:
    "Mints short-lived session tokens for downstream services. Each " +
    "token carries a 15-minute expiry and is invalidated on sign-out.",
  tools: [
    {
      name: "mint_session",
      description:
        "Mint a new session token for the caller. Token expires in " +
        "15 minutes.",
      input_schema: {
        type: "object",
        properties: {
          subject: { type: "string", maxLength: 128 },
        },
        required: ["subject"],
        additionalProperties: false,
      },
    },
  ],
  source_code: `
    import { sign } from "jsonwebtoken";

    const SESSION_TTL_MS = 15 * 60 * 1000;

    export async function mintSession(subject) {
      // Expiry is 15 minutes. Rotation is enforced: each sign-out
      // invalidates the active token and revokeByJti() is called.
      const nowMs = Date.now();
      const token = sign(
        {
          sub: String(subject),
          iat: Math.floor(nowMs / 1000),
          exp: Math.floor((nowMs + SESSION_TTL_MS) / 1000),
          jti: cryptoUuid(),
        },
        getSigningKey(),
        { algorithm: "RS256" },
      );
      return { token, ttl_ms: SESSION_TTL_MS };
    }

    function cryptoUuid() { return "jti-abc"; }
    function getSigningKey() { return "PRIVATE-KEY"; }
  `,
});
