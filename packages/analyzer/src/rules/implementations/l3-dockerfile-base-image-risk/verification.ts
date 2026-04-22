/**
 * L3 verification-step builders. Every step carries a structured Location
 * target. The sequence walks an auditor from the offending FROM line
 * through to the registry / DCT mitigation check.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { L3Fact } from "./gather.js";

/** Step 1 — open the offending FROM line. */
export function stepInspectFromInstruction(fact: L3Fact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the Dockerfile and jump to the FROM instruction. Confirm the base image ` +
      `reference matches the finding, paying attention to build-time argument ` +
      `substitution: a line like \`FROM \${BASE}\` where BASE has a non-digest default ` +
      `is equally unsafe. A Dockerfile inside a build context is authoritative — a ` +
      `.dockerignored copy is not.`,
    target: fact.location,
    expected_observation:
      fact.problem.kind === "no-tag"
        ? `A FROM instruction with no tag; Docker defaults to :latest.`
        : fact.problem.kind === "mutable-tag"
          ? `A FROM instruction whose tag contains the mutable keyword "${fact.problem.matchedKeyword}".`
          : `A FROM instruction whose image reference contains an unresolved build-time argument.`,
  };
}

/**
 * Step 2 — check the config-kind Location to record the auditor-readable
 * path plus json pointer.
 */
export function stepCheckConfigTarget(fact: L3Fact): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Record the Dockerfile path + FROM line number for the compliance report. ` +
      `The json_pointer \`/FROM/<line>\` is a stable reference even when the ` +
      `Dockerfile is edited — subsequent audits can diff against this pointer ` +
      `to confirm remediation (pinned digest present on the same logical stage).`,
    target: fact.configLocation,
    expected_observation:
      `A Dockerfile entry at ${fact.from.file}:${fact.from.line} naming the unpinned base image.`,
  };
}

/**
 * Step 3 — inspect sibling FROM instructions to quantify the mitigation.
 * A Dockerfile where N of M stages pin digests is partially mitigated;
 * this step gives the auditor the ratio.
 */
export function stepInspectMitigation(fact: L3Fact): VerificationStep {
  const target: Location = {
    kind: "config",
    file: fact.from.file,
    json_pointer: "/FROM",
  };
  return {
    step_type: "check-config",
    instruction:
      `Inspect every other FROM instruction in the same Dockerfile. Count how many pin ` +
      `a SHA256 digest and how many do not. A multi-stage build is only safe if EVERY ` +
      `stage is digest-pinned — a compromised builder stage still contaminates COPY ` +
      `--from=<stage> outputs consumed by an otherwise-pinned runtime stage.`,
    target,
    expected_observation:
      `${fact.pinnedStagesInFile} of ${fact.totalStagesInFile} FROM instructions ` +
      `pin a digest; the flagged stage does not.`,
  };
}

/**
 * Step 4 — verify no out-of-file mitigation (DCT, registry image signing
 * policy). This is a prompt to the auditor; static analysis cannot prove it.
 */
export function stepCheckRegistryPolicy(fact: L3Fact): VerificationStep {
  const target: Location = {
    kind: "config",
    file: fact.from.file,
    json_pointer: "/registry-policy",
  };
  return {
    step_type: "check-config",
    instruction:
      `Confirm there is no compensating registry-side policy (Docker Content Trust, ` +
      `Harbor / ECR / Quay image signing) that would reject an unpinned pull at build ` +
      `time. If such a policy is attached to the CI environment, the finding's ` +
      `confidence should be downgraded from "supply chain risk" to "posture gap".`,
    target,
    expected_observation:
      `No DCT / registry signing policy that would reject the unpinned FROM at pull time.`,
  };
}
