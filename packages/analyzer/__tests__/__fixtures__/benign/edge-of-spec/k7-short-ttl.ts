/**
 * Stresses K7 Long-Lived Tokens Without Rotation. Access tokens are
 * issued with a 15-minute TTL (900 seconds), and refresh is handled
 * elsewhere — the canonical short-TTL rotation pattern. K7 fires on
 * long TTLs; 900s is well below any reasonable threshold.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `const ACCESS_TOKEN_TTL_SECONDS = 900; // 15 minutes

export function issueAccessToken(userId: string): { token: string; ttl: number } {
  const token = signJwt({ sub: userId, exp: nowSeconds() + ACCESS_TOKEN_TTL_SECONDS });
  return { token, ttl: ACCESS_TOKEN_TTL_SECONDS };
}

declare function signJwt(claims: Record<string, unknown>): string;
declare function nowSeconds(): number;
`;

export const k7ShortTtlFixture: BenignFixture = {
  id: "edge-of-spec/k7-short-ttl",
  bucket: "edge-of-spec",
  why_benign:
    "K7 Long-Lived Tokens Without Rotation. Access TTL is 900s (15min) — " +
    "well below long-lived threshold, rotation handled separately.",
  context: {
    server: {
      id: "edge/k7-ttl",
      name: "short-ttl-auth",
      description: "Short-TTL access-token issuance.",
      github_url: null,
    },
    tools: [
      {
        name: "issue_access_token",
        description: "Issue a 15-minute access token for a user.",
        input_schema: {
          type: "object",
          properties: { user_id: { type: "string", format: "uuid" } },
          required: ["user_id"],
          additionalProperties: false,
        },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
