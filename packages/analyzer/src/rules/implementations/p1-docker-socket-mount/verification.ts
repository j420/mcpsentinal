/**
 * P1 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { P1Hit } from "./gather.js";

export function stepInspectSocketMount(hit: P1Hit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open ${hit.file} at line ${hit.line} and confirm the mount binds the ` +
      `${hit.spec.runtime} runtime socket (${hit.spec.path}) into the workload ` +
      `container. Check for named-volume aliases elsewhere in the same file — ` +
      `a volume declared as docker-sock:/var/run/docker.sock upstream and ` +
      `referenced here is still a live mount (charter lethal edge case #1).`,
    target: hit.location,
    expected_observation: hit.spec.description,
  };
}

export function stepRecordConfigPointer(hit: P1Hit): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Record the config json_pointer for the compliance bundle. Cross-reference ` +
      `CIS Docker Benchmark §5.31. This control is HIGH severity and applies ` +
      `uniformly across Docker / containerd / cri-o / podman.`,
    target: hit.configLocation,
    expected_observation: `Config pointer identifies the container-runtime socket mount.`,
  };
}

export function stepCheckReadOnlyClaim(hit: P1Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/volumes/readonly-claim",
  };
  return {
    step_type: "check-config",
    instruction:
      `If the mount carries :ro or readOnly: true, treat it IDENTICALLY to a ` +
      `writable mount (charter lethal edge case #5). The Docker API accepts ` +
      `container-create calls over the socket regardless of inode write ` +
      `permissions — read-only is not a mitigation.`,
    target,
    expected_observation: hit.readonlyFlag
      ? `Read-only flag present — DOES NOT reduce severity.`
      : `No read-only flag — standard writable socket mount.`,
  };
}

export function stepCheckSocketProxyAlternative(hit: P1Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/alternatives/docker-socket-proxy",
  };
  return {
    step_type: "check-config",
    instruction:
      `Determine whether the workload could use docker-socket-proxy (tecnativa/ ` +
      `linuxserver variants) instead of the raw socket. The proxy exposes specific ` +
      `API verbs over TCP — most "list containers" / "stream logs" use cases need ` +
      `only GET verbs and can be satisfied without granting container-create. If ` +
      `the workload truly needs create/exec, CI runners should use Kaniko or ` +
      `rootless Docker instead.`,
    target,
    expected_observation:
      `Operator classifies the workload: (a) list/log-only → migrate to ` +
      `socket-proxy with minimal verbs, (b) build pipeline → migrate to Kaniko / ` +
      `rootless Docker, (c) genuine orchestration need → explicit risk acceptance.`,
  };
}
