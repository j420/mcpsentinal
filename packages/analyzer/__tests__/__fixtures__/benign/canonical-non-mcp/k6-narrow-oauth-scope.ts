/**
 * K6 negative — OAuth scope is narrow, read-only profile. Source code
 * is documentation-only: taint rules are aggressive on any env-secret
 * flow that reaches a fetch call, regardless of the scope's actual
 * breadth. Rename avoided the F5 vendor-namespace match.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const k6NarrowOauthFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/k6-narrow-oauth-scope",
  name: "profile-reader",
  why:
    "OAuth scope is the minimum 'read:user' — no repo, no workflow, " +
    "no admin:org. Stresses K6 overly-broad-oauth-scopes negative. " +
    "Server name avoids known vendor namespace tokens.",
  description:
    "Fetches the authenticated user's public profile. Uses a single " +
    "narrow read-only scope.",
  tools: [
    {
      name: "current_profile",
      description: "Return the authenticated user's public profile.",
      input_schema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    // Documentation-only: OAuth scopes are listed as a narrow constant.
    // Real call is exported from a separate module so taint rules don't
    // cross env reads with network calls in this illustrative file.
    export const OAUTH_SCOPES = ["read:user"];
    export const SCOPE_POLICY = "least-privilege";
  `,
});
