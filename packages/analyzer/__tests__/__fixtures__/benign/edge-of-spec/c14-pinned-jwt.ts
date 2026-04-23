/**
 * Stresses C14 JWT Algorithm Confusion. Verification explicitly pins
 * `algorithms: ["RS256"]`, rejects `ignoreExpiration`, and passes a
 * public key (not a symmetric secret). C14 fires on 'none' algorithm,
 * missing algorithm pinning, or ignoreExpiration:true; this fixture
 * is the fully-locked-down shape.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `import jwt from "jsonwebtoken";

const PUBLIC_KEY = process.env.JWT_PUBLIC_KEY ?? "";

export function verifyToken(token: string): jwt.JwtPayload {
  const decoded = jwt.verify(token, PUBLIC_KEY, {
    algorithms: ["RS256"],
    // ignoreExpiration defaults to false; we leave it unset on purpose.
  });
  if (typeof decoded === "string") {
    throw new Error("unexpected string payload");
  }
  return decoded;
}
`;

export const c14PinnedJwtFixture: BenignFixture = {
  id: "edge-of-spec/c14-pinned-jwt",
  bucket: "edge-of-spec",
  why_benign:
    "C14 JWT Algorithm Confusion. algorithms pinned to ['RS256'], no " +
    "ignoreExpiration, asymmetric public key — fully hardened shape.",
  context: {
    server: {
      id: "edge/c14-jwt",
      name: "jwt-verifier",
      description: "RS256-pinned JWT verifier.",
      github_url: null,
    },
    tools: [
      {
        name: "verify_token",
        description: "Verify an RS256-signed JWT against the configured public key.",
        input_schema: {
          type: "object",
          properties: { token: { type: "string", maxLength: 4096 } },
          required: ["token"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true },
      },
    ],
    source_code: sourceCode,
    dependencies: [
      {
        name: "jsonwebtoken",
        version: "9.0.2",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-05"),
      },
    ],
    connection_metadata: null,
  },
};
