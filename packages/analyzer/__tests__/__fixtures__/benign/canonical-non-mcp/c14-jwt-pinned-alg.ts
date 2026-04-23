/**
 * C14 negative — jwt.verify with an explicit algorithms allowlist
 * pinned to RS256. No algorithm confusion possible.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const c14JwtPinnedAlgFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/c14-jwt-pinned-algorithms",
  name: "token-gate",
  why:
    "jwt.verify pins algorithms to ['RS256'] — rejects 'none' and any " +
    "HS* variant. Stresses C14 JWT algorithm-confusion negative.",
  description:
    "Verifies a bearer token and returns the authenticated subject. " +
    "Tokens must be signed with the configured RS256 public key.",
  tools: [
    {
      name: "whoami",
      description: "Return the authenticated subject for the bearer token.",
      input_schema: {
        type: "object",
        properties: {
          bearer: { type: "string", maxLength: 4096 },
        },
        required: ["bearer"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    import jwt from "jsonwebtoken";
    import { readFileSync } from "node:fs";

    const PUBLIC_KEY = readFileSync("/etc/app/jwt-public.pem", "utf8");

    export async function whoami(bearer) {
      const decoded = jwt.verify(bearer, PUBLIC_KEY, {
        algorithms: ["RS256"],
        issuer: "auth.example.com",
        audience: "api.example.com",
      });
      return { subject: decoded.sub };
    }
  `,
});
