import type { VerificationStep } from "../../../evidence.js";
import type { MaliciousPackageSite } from "./gather.js";

export function stepConsultAdvisory(site: MaliciousPackageSite): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Open the advisory URL and confirm the package "${site.matchedName}" is listed as ` +
      `malicious. Advisory: ${site.spec.advisory_url}. Summary: ${site.spec.incident_summary}.`,
    target: site.dependencyLocation,
    expected_observation:
      `The advisory at ${site.spec.advisory_url} explicitly names "${site.matchedName}" as a ` +
      `confirmed malicious package or typosquat.`,
  };
}

export function stepInspectManifest(site: MaliciousPackageSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Open the project manifest at the RFC 6901 pointer and remove the dependency "${site.name}". ` +
      `If the package entered via overrides / resolutions / pip constraints, strip it from that ` +
      `chain as well. After removal, regenerate the lockfile and audit the build environment for ` +
      `any artifacts the package may have written at install time.`,
    target: site.configLocation,
    expected_observation:
      `Manifest no longer references "${site.name}"; lockfile regenerated; install-time artifacts ` +
      `audited.`,
  };
}

export function stepCheckPostinstall(site: MaliciousPackageSite): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      `Inspect the lockfile for "${site.name}" and look for a postinstall / preinstall / prepare ` +
      `hook entry. The reference incident for this package (${site.spec.incident_summary}) relied ` +
      `on install-time code execution — if the lockfile records a hook, the build environment may ` +
      `already be compromised and requires full audit.`,
    target: site.dependencyLocation,
    expected_observation:
      `Lockfile either confirms an install hook (treat build env as compromised) or shows no ` +
      `hooks (limits blast radius to first-import only).`,
  };
}
