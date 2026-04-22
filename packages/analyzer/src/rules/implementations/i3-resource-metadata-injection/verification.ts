/**
 * I3 verification-step builders. All targets are structured Locations.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { I3Fact } from "./gather.js";

export function stepInspectResourceMetadata(fact: I3Fact): VerificationStep {
  const target: Location = {
    kind: "resource",
    uri: fact.resource_uri,
    field: fieldKind(fact),
  };
  const matched = fact.hits.map((h) => `${h.matched_field}:${h.key}`).join(", ");
  return {
    step_type: "inspect-description",
    instruction:
      `Open the resource declaration for "${fact.resource_name}". Inspect the ` +
      `name, description, and URI fields. The gather step matched the ` +
      `following injection-phrase catalogue entries: ${matched}. Confirm ` +
      `whether the phrasing is legitimate (documentation, tutorial quoting) ` +
      `or a behavioural directive aimed at the AI client.`,
    target,
    expected_observation:
      "The metadata contains a role-override, delimiter, or action directive " +
      "token sequence matching the shared INJECTION_PHRASES catalogue.",
  };
}

export function stepCompareAgainstToolA1(fact: I3Fact): VerificationStep {
  const target: Location = {
    kind: "resource",
    uri: fact.resource_uri,
    field: "description",
  };
  return {
    step_type: "compare-baseline",
    instruction:
      "Check whether the same server ALSO triggers A1 (prompt injection in " +
      "tool description) — a resource-level injection paired with a tool-" +
      "level injection is a coordinated prompt-injection campaign across " +
      "protocol surfaces, not an accidental quoting incident.",
    target,
    expected_observation:
      "The cross-surface pattern confirms deliberate injection.",
  };
}

function fieldKind(fact: I3Fact): "name" | "description" | "uri" | undefined {
  const first = fact.hits[0];
  if (!first) return undefined;
  if (first.matched_field === "combined") return "description";
  return first.matched_field;
}
