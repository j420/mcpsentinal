/**
 * K9 verification-step builders.
 *
 * Every step's target is a structured Location (config-kind for JSON
 * install hooks, source-kind for Python cmdclass finds).
 */

import type { VerificationStep } from "../../../evidence.js";
import type { K9Fact } from "./gather.js";

export function stepInspectHook(fact: K9Fact): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Open the install-hook body at this location and confirm it really ` +
      `runs during dependency installation. For package.json, the relevant ` +
      `lifecycle hooks are postinstall / preinstall / install. For Python, ` +
      `the cmdclass override's \`run()\` method runs at setup.py install ` +
      `time.`,
    target: fact.location,
    expected_observation:
      `Install hook \`${fact.hook}\` contains the token \`${fact.matchedToken.slice(0, 60)}\`, ` +
      `a signature of the ${fact.family} attack family. Snippet: ` +
      `${fact.hookSnippet.slice(0, 160)}`,
  };
}

export function stepTraceDangerousFamily(fact: K9Fact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Verify the matched token really indicates the ${fact.family} attack ` +
      `class. Legitimate build tooling (node-gyp, tsc, prebuild, esbuild, ` +
      `cmake) should be present without accompanying fetch / pipe-to-shell / ` +
      `base64-decode tokens. If both are present, the hook is dangerous.`,
    target: fact.location,
    expected_observation: fact.description,
  };
}

export function stepReviewInstallTimePrivileges(fact: K9Fact): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      `Confirm the impact surface: this package is installed with the ` +
      `calling user's FULL privileges (developer machine, CI runner) before ` +
      `any runtime security tooling has a chance to examine it. The ` +
      `payload fires at \`npm install\` / \`pip install\` time.`,
    target: fact.location,
    expected_observation:
      "Install hooks execute during dependency resolution with the user's " +
      "privileges — there is no sandbox between the hook and the host OS.",
  };
}
