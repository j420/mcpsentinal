/**
 * P6 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { P6Hit } from "./gather.js";

export function stepInspectHijackSite(hit: P6Hit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open ${hit.file} at line ${hit.line} and confirm the ${hit.pattern.id} ` +
      `variant is live. For the LD_PRELOAD / DYLD_INSERT_LIBRARIES forms, trace ` +
      `the library path back to its definition — hard-coded libssl / libcrypto ` +
      `is usually legitimate; variable paths or /tmp / /dev/shm paths are ` +
      `hijack vectors.`,
    target: hit.location,
    expected_observation: hit.pattern.description,
  };
}

export function stepRecordConfigPointer(hit: P6Hit): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Record the config json_pointer for the compliance bundle. Cross-reference ` +
      `CVE-2010-3856 (LD_AUDIT / LD_PRELOAD setuid escape) and the SANS LD_PRELOAD ` +
      `rootkits whitepaper. These primitives form the classic Linux userspace ` +
      `rootkit loadout.`,
    target: hit.configLocation,
    expected_observation: `Config pointer identifies the ${hit.pattern.id} hijack site.`,
  };
}

export function stepCheckPathControl(hit: P6Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/hijack/path-control",
  };
  return {
    step_type: "inspect-source",
    instruction:
      `Determine whether the library / memory target path is attacker-controlled. ` +
      `Trace shell / environment expansion, $variables, /tmp / /var/tmp / /dev/shm ` +
      `paths. Attacker-controlled paths convert the hijack from "architectural ` +
      `weakness" to "active exploit primitive". Hard-coded paths to trusted ` +
      `libraries (libssl.so.3, /usr/lib/libcrypto.so) remain flagged but have ` +
      `lower remediation urgency.`,
    target,
    expected_observation: hit.variablePath
      ? `Target path is variable or bare identifier — treat as attacker-controlled.`
      : `Target path is a hard-coded literal — operator review for legitimacy.`,
  };
}

export function stepCheckAlternativePattern(hit: P6Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/hijack/alternative",
  };
  return {
    step_type: "check-config",
    instruction:
      `If the workload legitimately needs library preloading (e.g., OpenTelemetry ` +
      `auto-instrumentation, jemalloc swap), document the justification in the ` +
      `compliance bundle. The remediation pathway for legitimate use is: (1) ` +
      `deploy the library via the container image only, never via ` +
      `/etc/ld.so.preload; (2) ensure the library file is root:root, mode 0755 ` +
      `(not writable by non-root); (3) add a file-integrity monitoring rule on ` +
      `the library path.`,
    target,
    expected_observation:
      `Operator classifies the workload: legitimate instrumentation vs. architectural weakness.`,
  };
}
