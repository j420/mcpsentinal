/**
 * P2 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { P2Hit } from "./gather.js";

export function stepInspectCapabilityDeclaration(hit: P2Hit): VerificationStep {
  const descriptor =
    hit.kind === "capability"
      ? `CAP_${hit.spec.name} declaration`
      : `${hit.spec.key}: ${hit.spec.id === "hostUsers-false" ? "false" : "true"} declaration`;
  return {
    step_type: "inspect-source",
    instruction:
      `Open ${hit.file} at line ${hit.line} and confirm the ${descriptor} is live ` +
      `(not inside a docs-only block or commented-out example). For Kubernetes ` +
      `manifests, verify whether the declaration is pod-level or container-level ` +
      `— the rule reports each distinct declaration once (charter lethal edge #5).`,
    target: hit.location,
    expected_observation: hit.spec.description,
  };
}

export function stepRecordConfigPointer(hit: P2Hit): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Record the config json_pointer for the compliance bundle. Cross-reference ` +
      `CIS Docker Benchmark §5.3-5.22 (depending on variant) or Kubernetes PSS ` +
      `Restricted (no privileged, no host namespaces, no capability adds beyond ` +
      `NET_BIND_SERVICE).`,
    target: hit.configLocation,
    expected_observation:
      hit.kind === "capability"
        ? `Config pointer identifies the dangerous capability add.`
        : `Config pointer identifies the host-namespace or privileged-mode declaration.`,
  };
}

export function stepCheckDropAllCompanion(hit: P2Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/securityContext/capabilities/drop",
  };
  const dropAll = hit.kind === "capability" ? hit.dropAllCompanion : false;
  return {
    step_type: "check-config",
    instruction:
      `If the spec contains cap_drop: ALL AND cap_add: <dangerous>, the add is ` +
      `what matters — cap_drop is NOT a compensating control when paired with a ` +
      `dangerous add (charter lethal edge case #2). Confirm the drop-all + add ` +
      `combination before dismissing the finding.`,
    target,
    expected_observation: dropAll
      ? `drop: ALL IS present in the same securityContext — does not mitigate the add.`
      : `No drop block — capability add is applied on top of the default set.`,
  };
}

export function stepCheckSeccompAppArmor(hit: P2Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/securityContext/seccompProfile",
  };
  return {
    step_type: "check-config",
    instruction:
      `Determine whether a restrictive seccomp / AppArmor profile is attached to ` +
      `the workload. A "RuntimeDefault" or tighter profile materially reduces ` +
      `exploitation confidence for ${hit.spec.description.slice(0, 80)}... but ` +
      `does NOT change this finding — the capability / namespace is still present ` +
      `and the posture is still non-compliant with CIS / PSS Restricted.`,
    target,
    expected_observation:
      `Operator confirms whether seccompProfile.type is RuntimeDefault (or ` +
      `tighter Localhost) and records it in the compliance bundle.`,
  };
}
