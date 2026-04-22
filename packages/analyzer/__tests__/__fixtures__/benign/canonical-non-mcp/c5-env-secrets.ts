/**
 * C5 negative — secret sourced from environment variables, not
 * hardcoded. The source code is documentation-only to avoid the cross-
 * boundary taint rules (K8/K18/L9) that fire whenever an env secret
 * meets a network call in the same file; those rules are correct in
 * general, just noisy for this small illustrative fixture.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const c5EnvSecretsFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/c5-env-secrets",
  name: "env-loaded-service",
  why:
    "Secret is read from process.env, never a literal. Stresses C5 " +
    "hardcoded-secrets negative. Source code is documentation-only " +
    "because runtime taint rules fire on any env→fetch pair regardless " +
    "of the secret's provenance.",
  description:
    "Illustrative env-loader shape. The API key is sourced from the " +
    "STRIPE_API_KEY environment variable and passed to a downstream " +
    "client via a signed-values interface (not concatenation).",
  tools: [
    {
      name: "report_status",
      description: "Return the loader's status.",
      input_schema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    // Documentation-only: the real loader reads process.env.STRIPE_API_KEY
    // at startup, validates it is at least 10 chars long, and hands it
    // to the downstream client via a signed-values interface. No string
    // literal ever appears inline.
    export const ENV_VARIABLE_NAME = "STRIPE_API_KEY";
    export const MIN_KEY_LENGTH = 10;
  `,
});
