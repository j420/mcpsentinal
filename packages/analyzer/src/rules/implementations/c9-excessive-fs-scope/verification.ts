/**
 * C9 verification-step builders — every step's `target` is a structured
 * Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { FsScopeFact, C9LeakKind } from "./gather.js";

function describeKind(kind: C9LeakKind): string {
  switch (kind) {
    case "fs-list-root":
      return "a filesystem listing call rooted at /";
    case "fs-read-root":
      return "a filesystem read call rooted at /";
    case "chdir-root":
      return "a working-directory change to /";
    case "base-path-root":
      return "a base / allowed-paths configuration set to /";
    case "python-walk-root":
      return "a Python os.walk('/') / Path('/').iterdir() / os.listdir('/') call";
  }
}

export function stepInspectRootCall(fact: FsScopeFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the call really takes ` +
      `the root directory as its filesystem scope. If the deployment runs ` +
      `under a Docker user namespace or unshare with a private root, the ` +
      `practical impact is mitigated; otherwise the AI agent has read (and ` +
      `possibly write) access to every file the host process can touch.`,
    target: fact.location,
    expected_observation:
      `${describeKind(fact.kind)}. Observed: \`${fact.observed}\`.`,
  };
}

export function stepCheckClampHelper(fact: FsScopeFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      fact.clampHelperPresent
        ? `A charter-clamp helper (isSubpath / resolveWithin / safeJoin / ` +
          `ensureInside / validatePath) was detected somewhere in the ` +
          `source. Confirm it actually clamps the path BEFORE the ` +
          `root-rooted call — a clamp that fires AFTER the dangerous ` +
          `operation does nothing.`
        : `No charter-clamp helper (isSubpath / resolveWithin / safeJoin / ` +
          `ensureInside / validatePath) was found anywhere in the source. ` +
          `The root scope is unclamped — every path the agent supplies ` +
          `will be honoured against the entire filesystem.`,
    target: fact.location,
    expected_observation:
      fact.clampHelperPresent
        ? "A clamp helper exists somewhere in the file but its order relative to the root call needs review."
        : "No clamp helper anywhere in the source — root scope is fully unclamped.",
  };
}

export function stepCheckDeploymentSandbox(fact: FsScopeFact): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Inspect the deployment configuration (Docker user / userns-remap, ` +
      `Kubernetes securityContext.runAsUser, systemd-nspawn, chroot) for ` +
      `OS-level isolation that constrains the filesystem view. The static ` +
      `analyser cannot resolve these — a regulator will accept either ` +
      `(a) a charter clamp helper in code OR (b) verified OS-level isolation, ` +
      `but not both absent.`,
    target: fact.location,
    expected_observation:
      "Deployment manifest documents an OS-level filesystem boundary that constrains the root scope.",
  };
}
