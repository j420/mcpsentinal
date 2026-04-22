/**
 * M4 verification steps — named factories, structured Location targets.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { SquatSite } from "./gather.js";

export function stepInspectClaims(site: SquatSite): VerificationStep {
  const classes = Array.from(new Set(site.matched_signals.map((m) => m.cls))).join(", ");
  return {
    step_type: "inspect-description",
    instruction:
      `Open the tool's description in the registry. Confirm the following ` +
      `authority/authenticity signal classes are present: ${classes || "(bare vendor token)"}. ` +
      `Each matched class is an independent tool-selection-biasing claim.`,
    target: site.location,
    expected_observation:
      `Tool "${site.tool_name}" description asserts authority via ` +
      `${site.matched_signals.length} signal(s)` +
      (site.bare_vendor_token ? ` plus a bare vendor token "${site.bare_vendor_token}".` : "."),
  };
}

export function stepVerifyVendorAttestation(site: SquatSite): VerificationStep {
  const vendor = site.bare_vendor_token ??
    site.matched_signals.find((m) => m.cls === "vendor-attribution")?.matched_text;
  return {
    step_type: "check-dependency",
    instruction:
      vendor
        ? `The description claims affiliation with "${vendor}". Verify the ` +
          `package is published by that vendor on npm/PyPI. If the vendor ` +
          `namespace is not present in the package metadata, the claim is ` +
          `squatting.`
        : `No specific vendor claim — this step confirms there is also no ` +
          `covert vendor attestation (check package metadata for implicit ` +
          `vendor fields such as 'organization' or 'publisher').`,
    target: site.location,
    expected_observation:
      vendor
        ? `Package metadata does NOT list "${vendor}" as publisher.`
        : `Package metadata carries no implicit vendor claim.`,
  };
}

export function stepCheckNegation(site: SquatSite): VerificationStep {
  return {
    step_type: "inspect-description",
    instruction: site.has_negation
      ? `A negation token (not|no|unofficial|disclaimer|un-prefix) was detected ` +
        `near an authenticity anchor. Re-read the description and confirm that ` +
        `the author is honestly disclosing non-affiliation (e.g. "community ` +
        `unofficial fork") rather than performatively disclaiming while still ` +
        `making the squatting claim elsewhere.`
      : `No negation token detected. Confirm the description does not contain ` +
        `a disclaimer you would have expected a legitimate vendor-fork to include.`,
    target: site.location,
    expected_observation: site.has_negation
      ? `An honest disclaimer in the description body.`
      : `No disclaimer language — the authority claim stands.`,
  };
}
