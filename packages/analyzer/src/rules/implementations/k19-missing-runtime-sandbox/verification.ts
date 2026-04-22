/**
 * K19 verification-step builders. Each step carries a structured Location
 * target. The sequence walks an auditor from the disable flag through to
 * compensating-control and admission-controller checks.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { K19FlagHit } from "./gather.js";

/** Step 1 — inspect the line the flag lives on. */
export function stepInspectDisableFlag(hit: K19FlagHit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open ${hit.file} at line ${hit.line} and confirm the sandbox-disable flag is ` +
      `part of the active configuration — not a commented-out example, not a ` +
      `placeholder inside an env-only conditional that production overrides.`,
    target: hit.location,
    expected_observation: `Line ${hit.line} contains an active ${hit.flag.category} configuration: ${hit.flag.description}`,
  };
}

/** Step 2 — record the structured config pointer for audit evidence. */
export function stepRecordConfigPointer(hit: K19FlagHit): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Record the config json_pointer ${JSON.stringify((hit.configLocation as Extract<Location, { kind: "config" }>).json_pointer)} ` +
      `against ${hit.file} for the CIS §5.2 control evidence bundle. Cross-reference the ` +
      `flag's category (${hit.flag.category}) to the specific CIS subsection: privileged-mode → ` +
      `§5.2.1, host-namespace-share → §5.2.2–5.2.4, privilege-escalation → §5.2.5, ` +
      `security-profile-disable → §5.2.7, capability-addition → §5.2.9.`,
    target: hit.configLocation,
    expected_observation: `Config pointer resolves to the offending setting.`,
  };
}

/** Step 3 — check compensating controls in the same file. */
export function stepInspectCompensatingControls(hit: K19FlagHit, compensations: Set<string>): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/securityContext",
  };
  const present = [...compensations].sort();
  return {
    step_type: "check-config",
    instruction:
      `Scan the same file for compensating controls (runAsNonRoot, readOnlyRootFilesystem, ` +
      `no-new-privileges). If ANY compensating control is present alongside the flagged ` +
      `${hit.flag.category} flag, record both: the compensation does NOT suppress the ` +
      `finding (a privileged container neutralises runAsNonRoot at runtime) but it does ` +
      `lower exploitation confidence.`,
    target,
    expected_observation:
      present.length === 0
        ? `No compensating controls found alongside the flagged sandbox defeat.`
        : `Compensating controls present: ${present.join(", ")}. Finding remains valid per CHARTER lethal edge case #1.`,
  };
}

/** Step 4 — verify no admission-controller rewrite. */
export function stepCheckAdmissionControl(hit: K19FlagHit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/admission-controllers",
  };
  return {
    step_type: "check-config",
    instruction:
      `Check the deployment target (Kubernetes cluster / Docker daemon) for an admission ` +
      `controller that would reject or mutate this setting at apply time: Pod Security ` +
      `Admission (baseline or stricter), Kyverno / OPA Gatekeeper policy denying ` +
      `${hit.flag.category}, Docker daemon \`userns-remap\`. If such a control is ` +
      `present and enforced, downgrade the finding from "active gap" to "posture risk".`,
    target,
    expected_observation:
      `No admission controller rewriting or rejecting ${hit.flag.category} at deployment time.`,
  };
}
