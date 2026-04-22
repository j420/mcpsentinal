/**
 * L12 verification-step builders. Every VerificationStep.target is a
 * structured Location so the auditor can navigate directly to the
 * tamper site.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { L12Fact } from "./gather.js";

/** Step 1 — inspect the tamper command at the manifest or workflow site. */
export function stepInspectTamperSite(fact: L12Fact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      fact.kind === "manifest-lifecycle-tamper"
        ? `Open package.json and confirm the "${fact.hookOrWorkflow}" script runs ` +
          `AFTER the test step on the publisher's machine. npm guarantees the ` +
          `lifecycle ordering: test → postbuild / prepublishOnly / prepack → pack. ` +
          `The tamper verb(s) ${fact.tamperVerbs.join(", ")} target the ` +
          `${fact.buildDirs.join(", ")} build directory.`
        : `Open the workflow YAML at this line and confirm the step runs AFTER ` +
          `the test job. If the step is gated by \`needs: [test]\` (or the step ` +
          `follows "npm test" in the same job's sequence), the modification ` +
          `bypasses test coverage.`,
    target: fact.location,
    expected_observation:
      fact.kind === "manifest-lifecycle-tamper"
        ? `A post-test lifecycle hook that modifies build output.`
        : `A workflow step that modifies a build directory after test execution.`,
  };
}

/** Step 2 — reproduce the modification locally. */
export function stepReproduceModification(fact: L12Fact): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Run the build step in isolation (\`npm run build\`), hash the ` +
      `${fact.buildDirs.join(", ")} directory, then run the "${fact.hookOrWorkflow}" ` +
      `hook and hash again. Any hash delta confirms the post-test modification. ` +
      `Inspect the diff to decide whether it is a benign transformation ` +
      `(version stamp, licence banner) or a security-relevant change (injected ` +
      `import, removed integrity check, altered URL).`,
    target: fact.location,
    expected_observation:
      `${fact.buildDirs.join(", ")} files have different hashes before and after the hook.`,
  };
}

/** Step 3 — check for SLSA provenance mitigation. */
export function stepCheckProvenance(fact: L12Fact): VerificationStep {
  const target: Location = {
    kind: "config",
    file: "package.json",
    json_pointer: "/publishConfig/provenance",
  };
  return {
    step_type: "check-config",
    instruction: fact.provenancePresent
      ? `publishConfig.provenance is set. Confirm the package is published with ` +
        `\`npm publish --provenance\` and that the Sigstore attestation covers the ` +
        `FINAL tarball bytes — not the pre-tamper bytes. SLSA Build Level 2 says ` +
        `provenance must reflect what consumers install.`
      : `No publishConfig.provenance field is set. Without Sigstore attestation ` +
        `the consumer has no cryptographic way to detect that the installed ` +
        `bytes differ from what the test suite validated. Enable provenance ` +
        `AND verify the attestation covers the post-tamper artifact.`,
    target,
    expected_observation: fact.provenancePresent
      ? `publishConfig.provenance: true observed — partial mitigation.`
      : `No provenance — the tamper lands unverified.`,
  };
}
