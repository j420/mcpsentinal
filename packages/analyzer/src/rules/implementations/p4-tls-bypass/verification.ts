/**
 * P4 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { P4Hit } from "./gather.js";

export function stepInspectBypassSite(hit: P4Hit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open ${hit.file} at line ${hit.line} and confirm the TLS-bypass pattern is ` +
      `live (not gated on a dev-only NODE_ENV / TEST flag). For the ` +
      `${hit.pattern.id} variant, verify the scope: ` +
      `${hit.pattern.globalScope ? "GLOBAL — affects every HTTPS call in the process." : "local to this call / agent."}`,
    target: hit.location,
    expected_observation: hit.pattern.description,
  };
}

export function stepRecordConfigPointer(hit: P4Hit): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Record the config json_pointer for the compliance bundle. Cross-reference ` +
      `CWE-295 (Improper Certificate Validation) and OWASP TLS Cheat Sheet. If ` +
      `the justification is an internal CA, the correct remediation is CA pinning, ` +
      `not bypass — document the pinning strategy in the bundle.`,
    target: hit.configLocation,
    expected_observation: `Config pointer identifies the TLS-bypass pattern.`,
  };
}

export function stepCheckGlobalScope(hit: P4Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/tls/global-scope",
  };
  return {
    step_type: "check-config",
    instruction:
      `If the bypass is global-scope (NODE_TLS_REJECT_UNAUTHORIZED, or an Agent ` +
      `passed to a fetch default-options factory), every downstream library that ` +
      `issues HTTPS calls is compromised — including SDKs the developer may not ` +
      `know about. Trace the agent instantiation / env-var assignment to its ` +
      `effective reach.`,
    target,
    expected_observation: hit.pattern.globalScope
      ? `Global-scope bypass — every HTTPS call in the process is affected.`
      : `Local-scope bypass — limited to this call / agent instance.`,
  };
}

export function stepCheckAmplifier(hit: P4Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/tls/amplifier",
  };
  return {
    step_type: "inspect-source",
    instruction:
      `Check the same file for urllib3.disable_warnings / InsecureRequestWarning ` +
      `suppression. Presence of a warning-suppression call alongside a bypass ` +
      `indicates INTENTIONAL silent TLS bypass — a materially worse posture than ` +
      `an accidental verify=False.`,
    target,
    expected_observation: hit.amplifierPresent
      ? `Amplifier present — warnings are intentionally suppressed.`
      : `No amplifier — bypass stands alone.`,
  };
}
