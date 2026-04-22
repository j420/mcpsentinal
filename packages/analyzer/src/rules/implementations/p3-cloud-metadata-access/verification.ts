/**
 * P3 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { P3Hit } from "./gather.js";

export function stepInspectMetadataReference(hit: P3Hit): VerificationStep {
  const label =
    hit.kind === "endpoint"
      ? `${hit.spec.provider.toUpperCase()} metadata endpoint (${hit.spec.family})`
      : `IMDSv2 HttpPutResponseHopLimit = ${hit.value}`;
  return {
    step_type: "inspect-source",
    instruction:
      `Open ${hit.file} at line ${hit.line} and confirm the ${label} reference is ` +
      `not part of a block / deny / reject rule. Check the surrounding fetch / request / ` +
      `requests.get / http.Get / urllib call graph — a literal endpoint adjacent to an ` +
      `HTTP client is intent-to-fetch credentials.`,
    target: hit.location,
    expected_observation:
      hit.kind === "endpoint"
        ? hit.spec.description
        : `HttpPutResponseHopLimit of ${hit.value} exposes IMDSv2 to pod-level SSRF on ` +
          `EKS / GKE / AKS. The safe value is 1.`,
  };
}

export function stepRecordConfigPointer(hit: P3Hit): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Record the config json_pointer for the compliance bundle. Cross-reference ` +
      `the AWS IMDSv2 hardening guide and Capital One 2019 breach postmortem. For ` +
      `Kubernetes workloads, confirm whether a NetworkPolicy egress rule blocks ` +
      `CIDR 169.254.169.254/32 and fd00:ec2::/64 — both are independent posture ` +
      `controls.`,
    target: hit.configLocation,
    expected_observation:
      hit.kind === "endpoint"
        ? `Config pointer identifies a metadata-endpoint reference.`
        : `Config pointer identifies the IMDSv2 hop-limit inflation.`,
  };
}

export function stepCheckIMDSv2Enforcement(hit: P3Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/metadata/http-tokens",
  };
  return {
    step_type: "check-config",
    instruction:
      `Verify whether the instance profile / launch template enforces http-tokens ` +
      `required (IMDSv2 only). On AWS this prevents the unauthenticated ` +
      `IMDSv1-style fetch that the Capital One breach used. On GKE / AKS the ` +
      `equivalent is to confirm Workload Identity / MSI is in use instead of ` +
      `direct-metadata access.`,
    target,
    expected_observation:
      `Operator confirms IMDSv2 required (AWS) or Workload Identity / MSI (GCP / Azure) ` +
      `is enforced at the instance / pod level.`,
  };
}

export function stepCheckBlockRuleAbsent(hit: P3Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/network/egress-deny",
  };
  return {
    step_type: "check-config",
    instruction:
      `Confirm this reference is not adjacent to an egress-deny rule. Pairing ` +
      `the endpoint with a block / deny / reject primitive inverts the posture ` +
      `(defensive, not offensive) — if found, demote the finding to informational.`,
    target,
    expected_observation: `No block / deny / reject token on the same line.`,
  };
}
