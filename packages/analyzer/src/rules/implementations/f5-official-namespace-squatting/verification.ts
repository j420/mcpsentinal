/**
 * F5 verification-step builders — every step carries a structured
 * Location target (v2 standard §4). An auditor reads the steps,
 * opens the server's registry page + GitHub URL, and confirms the
 * namespace-mismatch.
 *
 * No regex, no long string-literal arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { F5Site } from "./gather.js";

/** Step — inspect the flagged server name. */
export function stepInspectServerName(site: F5Site): VerificationStep {
  return {
    step_type: "inspect-description",
    instruction:
      `Compare the observed server name "${site.serverName}" against the vendor ` +
      `namespace "${site.vendor.org}" (${site.vendor.vendor_display}). The scanner ` +
      `classified this match via the ${site.classifier} classifier with ` +
      `Damerau-Levenshtein distance ${site.distance}. If the server is an official ` +
      `${site.vendor.vendor_display} product, add its GitHub organisation to ` +
      `OFFICIAL_NAMESPACES.verified_github_orgs in the rule's data file.`,
    target: site.serverLocation,
    expected_observation:
      `Server name "${site.serverName}" ${describeMatch(site)} "${site.vendor.org}".`,
  };
}

/** Step — verify the publisher (github_url) against the vendor's verified orgs. */
export function stepVerifyPublisher(site: F5Site): VerificationStep {
  const verifiedList = site.vendor.verified_github_orgs
    .map((o) => `github.com/${o}/…`)
    .join(", ");
  return {
    step_type: "compare-baseline",
    instruction:
      `Open the server's repository at ${site.githubUrl ?? "(github_url missing)"} ` +
      `and confirm the owning organisation is NOT one of the vendor's verified orgs. ` +
      `The vendor registers the following orgs as authoritative: ${verifiedList}. A ` +
      `match against any of these suppresses the finding.`,
    target: site.serverLocation,
    expected_observation:
      site.githubUrl === null
        ? `github_url is missing — the rule cannot rule out impersonation.`
        : `The repository owner is NOT in the vendor's verified-org list.`,
  };
}

/** Step — investigate the registry page for publisher identity. */
export function stepInspectRegistryListing(site: F5Site): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Open the MCP registry page for "${site.serverName}" (Smithery, PulseMCP, or ` +
      `modelcontextprotocol.io/registry). Cross-reference the stated publisher ` +
      `identity against ${site.vendor.vendor_display}'s official publications. A ` +
      `recently published server with low install count and no vendor affiliation ` +
      `is the canonical squat pattern.`,
    target: site.serverLocation,
    expected_observation:
      `Registry publisher identity does not match ${site.vendor.vendor_display}; ` +
      `the server is an impersonator.`,
  };
}

function describeMatch(site: F5Site): string {
  switch (site.classifier) {
    case "substring-containment":
      return `directly contains the vendor token`;
    case "levenshtein-near":
      return `is ${site.distance} edit(s) from`;
    case "visual-confusable":
      return `contains a visual-confusable grapheme that normalises to "${site.normalizedVariant ?? "(unknown)"}" matching`;
    case "unicode-confusable":
      return `contains Unicode confusables that normalise to "${site.normalizedVariant ?? "(unknown)"}" matching`;
  }
}
