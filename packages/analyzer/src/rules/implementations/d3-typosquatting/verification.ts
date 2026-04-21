/**
 * D3 verification-step builders — every step carries a structured
 * Location target (v2 standard §4). The step list is what an auditor
 * reads to reproduce the observation: "open this file, compare these
 * names, confirm what the rule claims."
 *
 * No regex, no long string-literal arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { TyposquatSite } from "./gather.js";

/** Step — inspect the dependency entry itself. */
export function stepInspectDependency(site: TyposquatSite): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      `Open the manifest and confirm the dependency \`${site.candidate}@${site.version}\` is present. ` +
      `The scanner's similarity pipeline matched this name against the curated target ` +
      `\`${site.target}\` via the ${site.classifier} classifier. If this dependency is an ` +
      `intentional internal fork or re-export, add it to \`legitimate-forks.ts\` so the finding ` +
      `will no longer fire.`,
    target: site.dependencyLocation,
    expected_observation:
      `Dependency ${site.ecosystem}:${site.candidate}@${site.version} is declared; ` +
      `it is NOT in the legitimate-fork allowlist at scan time.`,
  };
}

/** Step — confirm the similarity measurement against the target. */
export function stepConfirmSimilarity(site: TyposquatSite): VerificationStep {
  const intro =
    site.classifier === "confirmed-typosquat"
      ? `This name is in the confirmed-typosquat advisory registry; no recomputation is ` +
        `necessary, but the auditor can corroborate by running the similarity command below.`
      : `Recompute the Damerau-Levenshtein distance and Jaro-Winkler similarity between ` +
        `\`${site.candidate}\` and \`${site.target}\` using the same primitives as the scanner.`;

  return {
    step_type: "check-dependency",
    instruction:
      `${intro} Concretely, the rule expects Damerau-Levenshtein ≤ ${site.targetMeta.max_distance} ` +
      `and Jaro-Winkler ≥ 0.80 (except for advisory-registry matches which skip the floor). ` +
      `Observed values: distance ${site.distance}, Jaro-Winkler ${site.jaroWinklerScore.toFixed(3)}.`,
    target: site.dependencyLocation,
    expected_observation:
      `Damerau-Levenshtein distance between "${site.candidate}" and "${site.target}" is ` +
      `${site.distance}. Jaro-Winkler is ${site.jaroWinklerScore.toFixed(3)}. The ` +
      `numbers agree with what the rule recorded.`,
  };
}

/** Step — point to the exact package.json (or pyproject.toml) line/pointer. */
export function stepInspectManifest(site: TyposquatSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Open the package manifest at this RFC 6901 pointer and read the line. ` +
      `Confirm the package name recorded in the manifest is literally \`${site.candidate}\` ` +
      `(not a spelling the build tool fuzzed to) and that no post-resolution rewrite turns ` +
      `this entry into the legitimate \`${site.target}\`.`,
    target: site.configLocation,
    expected_observation:
      `The manifest entry at ${renderPointer(site.configLocation)} resolves to ` +
      `${site.candidate}@${site.version} — the exact name the scanner flagged.`,
  };
}

/** Step — registry comparison (the manual investigation the rule cannot automate). */
export function stepCompareRegistry(site: TyposquatSite): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Open the ${site.ecosystem === "npm" ? "npm" : "PyPI"} page for \`${site.candidate}\` ` +
      `and compare against the legitimate \`${site.target}\`. Check: publisher identity, ` +
      `publish date, weekly download count, repository link, postinstall script presence. ` +
      `A typosquat typically presents as: recently published, low download count, no repository ` +
      `link, optionally carrying a postinstall hook that executes code at install time.`,
    target: site.dependencyLocation,
    expected_observation:
      `Either the candidate is a legitimate publisher-authored alternative (in which case ` +
      `add to \`legitimate-forks.ts\`) or its metadata confirms the typosquat hypothesis ` +
      `(recent, unknown publisher, low downloads, suspicious scripts).`,
  };
}

function renderPointer(loc: Location): string {
  if (loc.kind === "config") return `${loc.file}${loc.json_pointer}`;
  return "<config>";
}
