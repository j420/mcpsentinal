/**
 * L6 verification-step builders — every `target` is a structured
 * source-kind Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { L6Fact } from "./gather.js";

export function stepInspectCallSite(fact: L6Fact): VerificationStep {
  if (fact.kind === "symlink-creation") {
    return {
      step_type: "inspect-source",
      instruction:
        "Open the file at this line:col. Confirm the fs.symlink / " +
        "symlinkSync call really executes (is not behind a conditional " +
        "that is only reached in tests). Note which of the two arguments " +
        "is the TARGET (first) and which is the LINK PATH (second).",
      target: fact.location,
      expected_observation:
        `${fact.calleeName}(target, linkPath) where target contains ` +
        `"${fact.sensitiveTarget ?? "<unknown>"}". ` +
        `Observed: "${fact.observed.slice(0, 160)}".`,
    };
  }
  return {
    step_type: "inspect-source",
    instruction:
      "Open the file at this line:col. Confirm that the path passed to " +
      `${fact.calleeName} is user-controlled (derives from a request body, ` +
      "query parameter, or tool input). If it is a hard-coded constant, " +
      "the finding should be dismissed.",
    target: fact.location,
    expected_observation:
      `${fact.calleeName}(userControlledPath, …) — symlink-following ` +
      `filesystem call. Observed: "${fact.observed.slice(0, 160)}".`,
  };
}

export function stepInspectMitigation(fact: L6Fact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      fact.guardPresent || fact.nofollowPresent
        ? "Verify that the mitigation really defends this code path. A " +
          "realpath()/lstat() call preceding the read does NOT help if the " +
          "read happens on the original path. A correct defence uses fstat() " +
          "on the opened file descriptor, or opens with O_NOFOLLOW in the " +
          "same syscall. Check that the mitigation and the read share the " +
          "same file-descriptor identity."
        : "Verify that no symlink-following guard exists: search the " +
          "enclosing function for realpath / realpathSync / lstat / " +
          "lstatSync / O_NOFOLLOW / AT_SYMLINK_NOFOLLOW. The absence of " +
          "any such guard is the finding.",
    target: fact.location,
    expected_observation:
      fact.guardPresent && fact.nofollowPresent
        ? "Both a realpath-family guard and an O_NOFOLLOW flag were observed in scope — " +
          "the finding should only persist if the guard is on a different path " +
          "than the read call (TOCTOU race)."
        : fact.guardPresent
          ? "A realpath-family guard was observed but NO O_NOFOLLOW flag — " +
            "TOCTOU race window between guard and read."
          : fact.nofollowPresent
            ? "O_NOFOLLOW flag observed but NO realpath — attacker can " +
              "exploit relative-path containment bypass without the flag triggering."
            : "No symlink-aware mitigation of any kind in scope.",
  };
}

export function stepCheckBindMountBoundary(fact: L6Fact): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      "If this process runs inside a container or chroot, review the " +
      "runtime config (Dockerfile / docker-compose.yml / k8s pod spec) " +
      "for bind-mounts or volumes that expose host credential " +
      "directories into the workload. A bind-mount of ~/.ssh or ~/.aws " +
      "into the container makes the in-container path lookup look safe " +
      "to realpath() while still exposing sensitive bytes.",
    target: {
      kind: "config",
      file: "Dockerfile",
      json_pointer: "/volumes",
    },
    expected_observation:
      "No bind-mount of host credential directories into the workload. If " +
      "such a mount exists, no in-container realpath check can close the gap.",
  };
}
