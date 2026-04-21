/**
 * L1 — GitHub Actions Tag Poisoning: verification-step builders.
 *
 * Every step's `target` is a structured Location (config-kind for the
 * offending `uses:` / `run:` key). An auditor can paste the JSON
 * pointer into yq and land on the exact document node.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { L1Fact } from "./gather.js";
import type { Location } from "../../location.js";

export function stepInspectOffendingKey(fact: L1Fact): VerificationStep {
  if (fact.family === "pipe-to-shell-in-run") {
    return {
      step_type: "check-config",
      instruction:
        "Open the workflow file and navigate to the indicated `run:` step. " +
        "Confirm the step body actually runs (is not inside an `if:` that's " +
        "never true, is not a commented-out block). Pipe-to-shell runs at " +
        "CI time with the runner's full access to repository secrets.",
      target: fact.location,
      expected_observation:
        `\`run:\` body at this JSON pointer downloads remote content and pipes ` +
        `it to a shell interpreter. Observed: "${fact.observed.slice(0, 160)}".`,
    };
  }
  return {
    step_type: "check-config",
    instruction:
      "Open the workflow file and navigate to the indicated `uses:` key. " +
      "Confirm the ref is neither a 40-character commit SHA nor a known " +
      "first-party Action ref that the repository has consciously accepted " +
      "as an exception. Tag-poisoning requires only an upstream force-push.",
    target: fact.location,
    expected_observation:
      `\`uses: ${fact.observed}\` — ref classification: ${fact.family}. ` +
      `${fact.description}.`,
  };
}

export function stepCheckSignedCommit(fact: L1Fact): VerificationStep {
  const target: Location = fact.location;
  return {
    step_type: "check-dependency",
    instruction:
      "Navigate to the upstream Action repository on GitHub and verify " +
      "whether the referenced tag is tag-protected. Tag-protection prevents " +
      "force-push but is NOT the GitHub default. If the tag protection rule " +
      "does not exist, the ref is mutable regardless of how stable the " +
      "project appears.",
    target,
    expected_observation:
      fact.usesRef
        ? `Upstream repository https://github.com/${fact.usesRef.owner}/${fact.usesRef.repo} — ` +
          `confirm whether tag-protection is enabled for \`${fact.usesRef.ref}\` via ` +
          `Settings → Rules → Tag ruleset (or via branch protection in older UIs).`
        : "No upstream repository applies — this step can be skipped.",
  };
}

export function stepInspectMitigation(fact: L1Fact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction: fact.hardenRunnerPresent
      ? "A step-security/harden-runner step is present in this workflow. " +
        "Confirm it runs BEFORE the flagged step (harden-runner must execute " +
        "as the first job step to intercept malicious network calls from " +
        "downstream Actions)."
      : "No step-security/harden-runner step was detected in this workflow. " +
        "Add a `- uses: step-security/harden-runner@<sha>` step as the first " +
        "step of every job that touches secrets.",
    target: fact.location,
    expected_observation: fact.hardenRunnerPresent
      ? "Harden-runner runs first; any post-exploitation network egress " +
        "from the tag-poisoned Action would be caught in `block` mode."
      : "No runtime mitigation is in place. Every invocation of the flagged " +
        "ref runs with unmodified network and filesystem access to the runner.",
  };
}
