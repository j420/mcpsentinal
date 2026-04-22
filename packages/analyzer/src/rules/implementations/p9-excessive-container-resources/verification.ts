/**
 * P9 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { P9FlagHit } from "./gather.js";

export function stepInspectResourceDeclaration(hit: P9FlagHit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open ${hit.file} at line ${hit.line} and confirm the ${hit.rule.kind} limit is ` +
      `expressed as ${hit.rule.matchKind === "excessive-value" ? "an excessive numeric value" : "an unlimited/zero sentinel"}. ` +
      `For compose files, check BOTH the top-level \`resources.limits.${hit.rule.kind}\` and ` +
      `\`deploy.resources.limits.${hit.rule.kind}\` paths — a Swarm-only limit does not ` +
      `apply under \`docker compose up\`.`,
    target: hit.location,
    expected_observation: `${hit.rule.description}`,
  };
}

export function stepRecordConfigPointer(hit: P9FlagHit): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Record the config json_pointer for the compliance bundle. Cross-reference ` +
      `CIS Docker Benchmark §5.10–5.14: memory → §5.10, CPU → §5.11, PIDs → §5.12, ` +
      `ulimit → §5.13, open-files → §5.14. Each is an independent control; satisfying ` +
      `one does not compensate for missing the others.`,
    target: hit.configLocation,
    expected_observation: `Config pointer identifies the unlimited / excessive resource setting.`,
  };
}

export function stepCheckRequestsPresence(hit: P9FlagHit, requestsPresent: boolean): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/resources/requests",
  };
  return {
    step_type: "check-config",
    instruction: requestsPresent
      ? `Requests ARE set but limits are missing / unlimited — this is the worst ` +
        `failure mode of lethal edge case #1: the scheduler trusts the requests and ` +
        `packs the pod tightly, so an unbounded consumer now steals from its ` +
        `bin-packed neighbours. Remediation MUST add limits, not just tune requests.`
      : `Requests are also absent — the pod has no resource contract at all. ` +
        `Remediation: add BOTH requests and limits.`,
    target,
    expected_observation: requestsPresent
      ? `A requests block IS present in the spec.`
      : `No requests block in the spec.`,
  };
}

export function stepCheckNamespaceLimitRange(hit: P9FlagHit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/namespace/LimitRange",
  };
  return {
    step_type: "check-config",
    instruction:
      `Verify whether the destination Kubernetes namespace (or Docker daemon) has ` +
      `a namespace-level LimitRange / ResourceQuota / default-ulimits that would ` +
      `supply compensating defaults at admission time. A clean LimitRange downgrades ` +
      `the finding from "active gap" to "posture risk" — the pod still lacks its ` +
      `own contract, but the namespace rejects admission or injects defaults.`,
    target,
    expected_observation:
      `No LimitRange / ResourceQuota defaulting applies in the target namespace.`,
  };
}
