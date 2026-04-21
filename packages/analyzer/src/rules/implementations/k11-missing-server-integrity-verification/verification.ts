import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { LoaderSite } from "./gather.js";

export function stepInspectLoader(site: LoaderSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at the indicated line and confirm the runtime loader ` +
      `"${site.calleeLabel}" (classified as \`${site.kind}\`). Runtime ` +
      `loaders include dynamic import(), require() calls on runtime-derived ` +
      `specifiers, MCPClient / transport constructors, shell-mediated ` +
      `curl|bash patterns, and runtime package installs. Each bypasses the ` +
      `build-time dependency lockfile unless paired with an explicit ` +
      `integrity check.`,
    target: site.location,
    expected_observation:
      `Loader call \`${site.calleeLabel}\` present on a non-test code path, ` +
      `with no inline integrity guard.`,
  };
}

export function stepInspectIntegrityScope(site: LoaderSite): VerificationStep {
  const target: Location = site.enclosingFunctionLocation ?? site.location;
  const present = site.integrityMitigation.present;
  return {
    step_type: "inspect-source",
    instruction: present
      ? `Integrity evidence was observed on the lexical ancestor chain: ` +
        `${site.integrityMitigation.markers.slice(0, 4).join(", ")}. ` +
        `Confirm the integrity check applies to the SAME artefact that ` +
        `"${site.calleeLabel}" loads — a checksum computed for a ` +
        `different file is not a mitigation.`
      : `Walk the ancestor chain from "${site.calleeLabel}" up to the ` +
        `file top-level and confirm NO integrity-verifying call, ` +
        `integrity-bearing identifier, or integrity-manifest filename ` +
        `literal exists anywhere on the path. Candidates the rule ` +
        `inspected: createHash / createVerify / verifyIntegrity / sri.check ` +
        `/ integrity.json / checksums.txt / identifiers containing sha256 / ` +
        `digest / checksum.`,
    target,
    expected_observation: present
      ? `Integrity evidence present but requires manual applicability check.`
      : `No integrity evidence on the path from loader to file scope — the ` +
        `loaded artefact is accepted verbatim from its source.`,
  };
}
