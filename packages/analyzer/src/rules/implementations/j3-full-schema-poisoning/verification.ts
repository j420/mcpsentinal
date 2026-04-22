import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { J3Fact } from "./gather.js";

export function stepInspectSchema(fact: J3Fact): VerificationStep {
  const target: Location = {
    kind: "schema",
    tool_name: fact.tool_name,
    json_pointer: "/",
  };
  return {
    step_type: "inspect-schema",
    instruction:
      `Inspect tool "${fact.tool_name}" input_schema for injection in enum / ` +
      `title / const / default / examples fields. Matched catalogue entries: ` +
      `${fact.hits.map((h) => h.key).join(", ")}.`,
    target,
    expected_observation:
      "One or more non-description schema fields carry role-override / " +
      "action-directive / delimiter tokens.",
  };
}

export function stepCrossReferenceB5(fact: J3Fact): VerificationStep {
  const target: Location = { kind: "tool", tool_name: fact.tool_name };
  return {
    step_type: "compare-baseline",
    instruction:
      "B5 covers parameter-description injection. J3 extends to the rest of " +
      "the schema. Confirm whether this tool also trips B5 — coordinated " +
      "injection across description + schema is a stronger signal than " +
      "either field alone.",
    target,
    expected_observation:
      "Schema injection present; cross-check for B5 / B7 correlation.",
  };
}
