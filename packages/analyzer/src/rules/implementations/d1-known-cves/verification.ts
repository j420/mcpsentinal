/**
 * D1 verification-step builders. Every step carries a structured
 * Location target so a regulator can jump directly to the evidence.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { KnownCveSite } from "./gather.js";

/** Step — inspect the dependency itself in the manifest. */
export function stepInspectDependency(site: KnownCveSite): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      `Open the manifest and confirm that ${site.ecosystem}:${site.name}@${site.version} is declared. ` +
      `The auditor asserts this version is affected by: ${site.cveIds.join(", ")}. Compare the ` +
      `version string in the manifest byte-for-byte against what the rule recorded.`,
    target: site.dependencyLocation,
    expected_observation:
      `Manifest declares ${site.name} at exactly version ${site.version}; no patched pin is in ` +
      `place. The auditor's cve_ids list contains at least ${site.primaryCveId}.`,
  };
}

/** Step — cross-reference against the upstream NVD/OSV record. */
export function stepCrossReferenceAdvisory(site: KnownCveSite): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Open https://nvd.nist.gov/vuln/detail/${site.primaryCveId} and compare the affected-version ` +
      `range to the installed version ${site.version}. If multiple advisories are listed ` +
      `(${site.cveIds.join(", ")}), repeat for each. Confirm at least one advisory's affected ` +
      `range covers ${site.version}.`,
    target: site.dependencyLocation,
    expected_observation:
      `The NVD/OSV record for ${site.primaryCveId} lists an affected version range that includes ` +
      `${site.version}. A patched version is available or the advisory lists mitigations.`,
  };
}

/** Step — inspect the manifest pointer verbatim. */
export function stepInspectManifest(site: KnownCveSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Navigate to the RFC 6901 pointer in the project manifest and read the dependency line. ` +
      `Confirm the name and version the scanner reported match the manifest literal — and that no ` +
      `patched fork (overrides, resolutions, npm-shrinkwrap pin) has silently replaced the package.`,
    target: site.configLocation,
    expected_observation:
      `${site.ecosystem === "npm" ? "package.json" : "pyproject.toml"} contains ${site.name} at ` +
      `version ${site.version} with no override/resolution that points at a patched fork.`,
  };
}
