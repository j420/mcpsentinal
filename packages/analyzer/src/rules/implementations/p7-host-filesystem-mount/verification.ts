/**
 * P7 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { P7Hit } from "./gather.js";

export function stepInspectHostMount(hit: P7Hit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open ${hit.file} at line ${hit.line} and confirm the volume / mount / ` +
      `hostPath references ${hit.spec.path} (or a subPath extending it). ` +
      `Cross-check subPath fields in neighbouring lines — a hostPath of /var/run ` +
      `with subPath: docker.sock is still a socket mount in effect.`,
    target: hit.location,
    expected_observation: hit.spec.description,
  };
}

export function stepRecordConfigPointer(hit: P7Hit): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Record the config json_pointer for the compliance bundle. Cross-reference ` +
      `Kubernetes PSS Restricted (which forbids hostPath entirely) and CIS ` +
      `Kubernetes §5.2.3 / §5.2.9. The finding is a posture-gap record even when ` +
      `the workload legitimately needs host access — it must be annotated as an ` +
      `explicit exception in the namespace, not silently allowed.`,
    target: hit.configLocation,
    expected_observation: `Config pointer identifies the sensitive host-path mount.`,
  };
}

export function stepCheckReadOnlyClaim(hit: P7Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/volumes/readonly-claim",
  };
  return {
    step_type: "check-config",
    instruction:
      `If the mount carries :ro or readOnly: true, note that this is a reduction ` +
      `in the posture gap but NOT an elimination (charter lethal edge #4). Read-` +
      `only still exposes SSH host keys, /etc/shadow, kubelet credentials, and ` +
      `TLS certs. Remediation remains "narrow or remove the mount".`,
    target,
    expected_observation: hit.readonlyFlag
      ? `Read-only flag present — reduces but does not eliminate the gap.`
      : `No read-only flag — full read/write access to the sensitive path.`,
  };
}

export function stepCheckNarrowerAlternative(hit: P7Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/volumes/narrowing-alternatives",
  };
  return {
    step_type: "check-config",
    instruction:
      `Determine whether a narrower volume type satisfies the workload's need: ` +
      `ConfigMap / Secret for configuration / credentials, emptyDir for scratch, ` +
      `projected for combined-volume mounts, CSI for external storage. The ` +
      `Restricted profile accepts all of these; hostPath requires explicit ` +
      `exception. For CNI / node-exporter / kubelet-adjacent workloads, document ` +
      `the exception class and scope the hostPath to the smallest possible ` +
      `directory (e.g., /var/lib/kubelet/pki only, not /var/lib).`,
    target,
    expected_observation:
      `Operator classifies: (a) legitimate host-access workload (document + narrow), ` +
      `(b) misuse (switch to ConfigMap / Secret / emptyDir / CSI).`,
  };
}
