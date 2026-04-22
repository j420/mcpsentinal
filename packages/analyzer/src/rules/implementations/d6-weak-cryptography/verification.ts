import type { VerificationStep } from "../../../evidence.js";
import type { WeakCryptoSite } from "./gather.js";

export function stepCheckInstalledVersion(site: WeakCryptoSite): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      `Verify the installed version of ${site.name} against the safe minimum ` +
      `(${site.spec.safe_min_version ?? "no safe version — package must be replaced"}). The ` +
      `scanner observed ${site.version}.`,
    target: site.dependencyLocation,
    expected_observation:
      site.spec.safe_min_version === null
        ? `The package is fundamentally weak/abandoned — no upgrade exists; replacement is required.`
        : `The installed version (${site.version}) is strictly below the safe minimum ${site.spec.safe_min_version}.`,
  };
}

export function stepConsultCwe327(site: WeakCryptoSite): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Open the cited advisory and read the vulnerable-range statement. Advisory: ${site.spec.advisory_url}. ` +
      `Weakness class: ${site.spec.category}. Issue: ${site.spec.issue}.`,
    target: site.dependencyLocation,
    expected_observation:
      `The advisory confirms ${site.name} is in scope of the declared weakness and the installed ` +
      `version is affected.`,
  };
}

export function stepInspectManifest(site: WeakCryptoSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Open the project manifest at the RFC 6901 pointer and update the dependency. Recommended ` +
      `replacement: ${site.spec.replacement}.`,
    target: site.configLocation,
    expected_observation:
      `Manifest is updated to a safe version, or the dependency is replaced by the recommended ` +
      `alternative.`,
  };
}
