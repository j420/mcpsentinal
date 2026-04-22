/**
 * C7 verification-step builders — every step's `target` is a structured
 * Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { CorsLeakFact, CorsLeakKind } from "./gather.js";

function describeKind(kind: CorsLeakKind): string {
  switch (kind) {
    case "cors-options-wildcard":
      return "an explicit `origin: \"*\"` setting";
    case "cors-options-reflected":
      return "a reflected origin (origin: true / function returning true unconditionally)";
    case "cors-no-arguments":
      return "a bare cors() call which defaults to wildcard origin";
    case "set-header-wildcard":
      return "a manual setHeader('Access-Control-Allow-Origin', '*') call";
    case "python-cors-wildcard":
      return "Python CORS(...) configured with origins=\"*\" or a default wildcard";
  }
}

export function stepInspectCorsConfig(fact: CorsLeakFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the CORS configuration ` +
      `really is permissive. Replace it with an explicit allowlist: an ` +
      `array of host strings or a function that pins each origin against ` +
      `a known set. Reject everything else.`,
    target: fact.location,
    expected_observation:
      `${describeKind(fact.kind)}. Observed: \`${fact.observed}\`.`,
  };
}

export function stepInspectCredentialsFlag(fact: CorsLeakFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      fact.credentialsFlag
        ? `\`credentials: true\` is set in the same configuration. The ` +
          `combination of wildcard origin + credentials enables full ` +
          `cross-origin session abuse on browsers that allow it (and on ` +
          `every server-side proxy / fetch-with-keepalive client). This is ` +
          `an immediate-incident-class misconfiguration.`
        : `Confirm \`credentials: true\` is NOT also set in this ` +
          `configuration (or anywhere else in the surrounding middleware ` +
          `stack). Wildcard CORS without credentials is still high — but ` +
          `with credentials the severity escalates to immediate-incident.`,
    target: fact.location,
    expected_observation:
      fact.credentialsFlag
        ? "credentials: true is paired with wildcard / reflected origin in the same options literal."
        : "credentials flag absent or false in this configuration.",
  };
}

export function stepCheckPerRouteOverride(fact: CorsLeakFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Walk the rest of the file (and sibling middleware modules) for ` +
      `per-route CORS overrides — \`app.options("/admin", cors({ origin: ` +
      `"*" }))\` style. A global cors() that is restrictive is no ` +
      `protection if a single per-route override widens the policy.`,
    target: fact.location,
    expected_observation:
      "No per-route cors() override that re-introduces a wildcard or reflected origin.",
  };
}
