/**
 * K7 verification-step builders — every step carries a structured Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { K7Site, TokenCreationSite, ExpiryAssignmentSite } from "./gather.js";

/** Step — inspect the call / assignment site. */
export function stepInspectSite(site: K7Site): VerificationStep {
  const label =
    site.kind === "token-creation"
      ? `Open the token-creation call \`${site.callerLabel}(...)\` and read the options object.`
      : `Open the expiry property \`${site.propertyName}\` and confirm the assigned value.`;

  return {
    step_type: "inspect-source",
    instruction:
      `${label} Verify that the effective token lifetime is within policy: ` +
      `access tokens ≤ 24h, refresh tokens ≤ 30d. Confirm the value is NOT ` +
      `zero / null / undefined (disabled expiry) and that no sibling ` +
      `\`ignoreExpiration: true\` / \`verify: false\` nullifies the enforcement.`,
    target: site.location,
    expected_observation: summariseFindingKind(site),
  };
}

/** Step — confirm the duration parsing against the policy threshold. */
export function stepConfirmDuration(site: K7Site): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      site.durationSeconds !== null
        ? `Confirm the parsed duration of ${site.durationSeconds} seconds ` +
          `(${Math.round(site.durationSeconds / 86400)} days) exceeds the policy ` +
          `ceiling for a ${site.isRefreshToken ? "refresh" : "access"} token.`
        : `Confirm the expiry is entirely absent/disabled. Without a positive ` +
          `expiration duration, the issued token survives until key rotation, ` +
          `explicit revocation, or identity-provider-side invalidation.`,
    target: site.location,
    expected_observation:
      site.durationSeconds !== null
        ? `Duration ${site.durationSeconds}s > ${site.isRefreshToken ? "30 days" : "24 hours"}.`
        : `No duration present / duration set to 0, null, undefined, or equivalent.`,
  };
}

/** Step — search the file for a token rotation mechanism. */
export function stepCheckRotation(site: K7Site): VerificationStep {
  const target: Location =
    site.location.kind === "source"
      ? { kind: "source", file: site.location.file, line: 1, col: 1 }
      : site.location;
  return {
    step_type: "inspect-source",
    instruction:
      `Read the surrounding file looking for a refresh-token endpoint or ` +
      `rotation helper (\`refreshToken\`, \`rotateToken\`, \`reissueJwt\`). ` +
      `Without rotation, the long lifetime directly becomes an attacker's ` +
      `persistence window.`,
    target,
    expected_observation:
      `Either a rotation helper exists and is wired to the caller of this ` +
      `token-creation path (the finding remains, but impact may be moderated) ` +
      `or no rotation is wired at all (the finding is a dedicated compliance gap).`,
  };
}

function summariseFindingKind(site: K7Site): string {
  switch (site.findingKind) {
    case "no-expiry":
      return "No expiry property on the token-creation call.";
    case "disabled-expiry":
      return "Expiry explicitly disabled — value is 0/null/undefined or a disable flag.";
    case "excessive-expiry":
      return `Access-class token lifetime exceeds 24h${
        site.durationSeconds ? ` (observed ${site.durationSeconds}s)` : ""
      }.`;
    case "excessive-expiry-refresh":
      return `Refresh-class token lifetime exceeds 30d${
        site.durationSeconds ? ` (observed ${site.durationSeconds}s)` : ""
      }.`;
  }
}
