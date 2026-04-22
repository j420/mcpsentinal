import type { VerificationStep } from "../../../evidence.js";
import type { SpoofSite } from "./gather.js";

export function stepInspectLiteral(site: SpoofSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open this line and read the string literal. Confirm that it is emitted ` +
      `to the user (printed/logged/returned) rather than only used as a ` +
      `log message. A user-facing fake update notification is the attack.`,
    target: site.location,
    expected_observation:
      `String contains both ${site.notification_desc} and ${site.install_evidence}.`,
  };
}

export function stepCheckLegitimate(site: SpoofSite): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction: site.enclosing_has_legitimate_idiom
      ? `The enclosing scope references a legitimate update-checker library ` +
        `(update-notifier, dependabot, renovate, semver). Confirm the ` +
        `string is wired to THAT checker (not a hand-rolled fake).`
      : `No legitimate update-checker idiom found in the enclosing scope. ` +
        `The install command is presented without backing from a real ` +
        `version-check library.`,
    target: site.location,
    expected_observation: site.enclosing_has_legitimate_idiom
      ? `Wired to a real update-checker.`
      : `Hand-rolled update string.`,
  };
}

export function stepCheckExecPath(site: SpoofSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Trace how the string reaches the user. If it is handed to ` +
      `exec/spawn/child_process or printed with a copy-paste encouragement, ` +
      `the spoofing attack is live. If it is only logged internally, the ` +
      `severity is reduced to advisory.`,
    target: site.location,
    expected_observation:
      `String flows into a user-facing surface (stdout, HTTP response, ` +
      `tool response) rather than an internal log.`,
  };
}
