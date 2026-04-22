import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { B6Site } from "./gather.js";

export function stepInspectAdditional(site: B6Site): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "inspect-schema",
    instruction:
      `Open the input_schema for tool "${site.tool_name}" and confirm the value of ` +
      `additionalProperties.`,
    target: loc,
    expected_observation:
      site.variant === "explicit-true"
        ? `additionalProperties: true — arbitrary keys accepted.`
        : `additionalProperties unset — defaults to true — arbitrary keys accepted.`,
  };
}

export function stepPinFalse(site: B6Site): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "compare-baseline",
    instruction:
      `Set additionalProperties: false in the input_schema. Verify the handler ` +
      `still works for legitimate callers; expand the schema if a real parameter ` +
      `was previously carried through the additionalProperties loophole.`,
    target: loc,
    expected_observation: `additionalProperties: false is present and the handler ` +
      `rejects any undeclared key.`,
  };
}
