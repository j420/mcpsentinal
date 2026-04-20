/**
 * K6 verification-step builders — every step carries a structured
 * Location target (Rule Standard v2 §4).
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { ScopeAssignment } from "./gather.js";

/** Step 1 — open the assignment site. */
export function stepInspectAssignment(assignment: ScopeAssignment): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file and confirm that \`${assignment.propertyName}\` is being ` +
      `assigned a value at this location. The shape of the value is ` +
      `\`${assignment.valueShape}\`. Verify the assignment is on the normal ` +
      `control-flow path (not inside a dev-only branch, not inside a test harness).`,
    target: assignment.location,
    expected_observation:
      `An OAuth scope assignment of shape ${assignment.valueShape} at this ` +
      `source location: ${assignment.lineText.slice(0, 120)}`,
  };
}

/** Step 2 — inspect the broad-scope tokens the classifier identified. */
export function stepInspectBroadScopes(assignment: ScopeAssignment): VerificationStep {
  const listing = assignment.broadScopes
    .map((b) => `"${b.scope}" (${b.severity}, ${b.rationale})`)
    .join(", ");
  return {
    step_type: "inspect-source",
    instruction:
      `Confirm that the assigned value contains the flagged scope tokens: ` +
      `${listing || "(no tokens extracted — flagged because value is user-controlled)"}. ` +
      `Classification is by structural vocabulary check, not regex: wildcard ` +
      `tokens are exact "*"; admin tokens are case-insensitive exact matches; ` +
      `colon/dot-suffix checks use the last segment of the scope ID.`,
    target: assignment.valueLocation,
    expected_observation:
      `The value expression literally contains the listed tokens, or the ` +
      `value resolves to a user-controlled reference.`,
  };
}

/** Step 3 — if user-controlled, display the input chain. */
export function stepInspectUserInputChain(assignment: ScopeAssignment): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Trace the value expression backward. The classifier found it flows from ` +
      `an HTTP/MCP input surface: ${assignment.userInputChain.join(" → ")}. ` +
      `A user-controlled scope means an attacker can request broader ` +
      `permissions than the server intends unless the server enforces an ` +
      `allowlist. Confirm no allowlist validation exists before the ` +
      `assignment.`,
    target: assignment.valueLocation,
    expected_observation:
      `The value flows from a request/body/query/params/headers source; no ` +
      `allowlist validation intervenes before the scope is used.`,
  };
}

/** Step 4 — search the file for scope narrowing (role-based mapping). */
export function stepCheckScopeNarrowing(assignment: ScopeAssignment): VerificationStep {
  const loc: Location =
    assignment.location.kind === "source"
      ? { kind: "source", file: assignment.location.file, line: 1, col: 1 }
      : assignment.location;
  return {
    step_type: "inspect-source",
    instruction:
      `Read the top of this file and search for any role-based or context-` +
      `based scope narrowing: an IfStatement / SwitchStatement that reassigns ` +
      `\`${assignment.propertyName}\` to a narrower value for specific user ` +
      `roles, or a whitelist intersection (\`requested.filter(s => ALLOWED.includes(s))\`). ` +
      `Absence of such narrowing means the broad scope is the effective scope.`,
    target: loc,
    expected_observation:
      `No scope narrowing for this assignment — the classifier's finding is ` +
      `the effective scope at runtime.`,
  };
}
