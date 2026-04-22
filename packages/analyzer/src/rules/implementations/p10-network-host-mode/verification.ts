/**
 * P10 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { P10Hit } from "./gather.js";

export function stepInspectNetworkDeclaration(hit: P10Hit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open ${hit.file} at line ${hit.line}. Confirm this declaration IS live ` +
      `(not inside a doc-only block, not gated on a debug flag). The variant is ` +
      `${hit.pattern.id}; cross-check against the schema type — Kubernetes keys ` +
      `are camelCase (hostNetwork), compose keys are snake_case (network_mode).`,
    target: hit.location,
    expected_observation: hit.pattern.description,
  };
}

export function stepRecordConfigPointer(hit: P10Hit): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Record the config json_pointer for the compliance bundle. Cross-reference ` +
      `CIS Docker §5.9 (for Docker variants) or CIS Kubernetes §5.2.4 (for hostNetwork: ` +
      `true). Both are high-severity controls in multi-tenant clusters.`,
    target: hit.configLocation,
    expected_observation: `Config pointer identifies the host-network declaration.`,
  };
}

export function stepCheckIsolationAlternatives(
  hit: P10Hit,
  alternatives: Set<string>,
): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/network/alternatives",
  };
  const present = [...alternatives].sort();
  return {
    step_type: "check-config",
    instruction:
      `Scan the same file for compensating network-isolation controls: NetworkPolicy ` +
      `resources, bridge / overlay / internal networks, explicit --network=bridge. ` +
      `Compensating controls LOWER exploitation confidence but do NOT suppress the ` +
      `host-network finding — the shared namespace still enables ARP spoofing and ` +
      `host-port binding regardless of policy.`,
    target,
    expected_observation:
      present.length === 0
        ? `No compensating network-isolation controls found.`
        : `Compensating controls present: ${present.join(", ")}.`,
  };
}

export function stepCheckLegitimateException(hit: P10Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/workload/identity",
  };
  return {
    step_type: "check-config",
    instruction:
      `Determine whether this workload is in the legitimate-exception class: CNI ` +
      `plugin, node-exporter, ingress controller, service-mesh sidecar. If YES, the ` +
      `finding is evidence of a posture requirement, not a misconfiguration — ` +
      `remediation shifts to adding NetworkPolicy + egress controls rather than ` +
      `removing hostNetwork. If NO, standard remediation applies.`,
    target,
    expected_observation:
      `Operator classifies the workload as EITHER a legitimate exception (document, add ` +
      `egress control) OR a regular pod (remediation: switch to bridge/overlay).`,
  };
}
