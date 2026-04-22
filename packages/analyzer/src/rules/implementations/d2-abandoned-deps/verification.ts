import type { VerificationStep } from "../../../evidence.js";
import type { AbandonedSite } from "./gather.js";

export function stepCheckPublishDate(site: AbandonedSite): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      `Open the ${site.ecosystem === "npm" ? "npm" : "PyPI"} page for ${site.name} and read ` +
      `the latest publish date. Confirm no newer version has been published since the scanner's ` +
      `snapshot (${site.lastUpdated}). If a newer release exists, the finding is stale — regenerate ` +
      `the dependency audit.`,
    target: site.dependencyLocation,
    expected_observation:
      `The registry reports the latest publish of ${site.name} is still ${site.lastUpdated} ` +
      `(≥${site.ageMonths} months ago). No newer version has been published.`,
  };
}

export function stepCheckRepoActivity(site: AbandonedSite): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Open the source repository (if registry metadata links one) and inspect the commit log, ` +
      `open issues, and open pull requests. Abandonment is supported by: no commits in the same ` +
      `window, open security issues without triage, repo archived by the maintainer, or an unmerged ` +
      `"take over maintenance" fork with traction.`,
    target: site.dependencyLocation,
    expected_observation:
      `The repository shows dormant or archived status, outstanding security issues, or an ` +
      `unmerged maintenance-takeover fork.`,
  };
}

export function stepInspectManifest(site: AbandonedSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Navigate to the RFC 6901 pointer in the manifest and confirm the exact dependency entry. ` +
      `A manifest-level override (npm overrides, pnpm.overrides, pip constraints) may silently pin ` +
      `a maintained fork — inspect for that before concluding the package is abandoned in this ` +
      `project.`,
    target: site.configLocation,
    expected_observation:
      `The manifest entry references ${site.name}@${site.version} with no override or resolution ` +
      `pointing at a maintained fork.`,
  };
}
