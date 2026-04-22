import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { J6Hit } from "./gather.js";

export function stepInspectDescription(hit: J6Hit): VerificationStep {
  const target: Location = { kind: "tool", tool_name: hit.tool_name };
  return {
    step_type: "inspect-description",
    instruction:
      `Review tool "${hit.tool_name}" description for preference-manipulation ` +
      `language. Matched ${hit.spec_key} (${hit.spec.kind}). Determine whether ` +
      `the phrasing is legitimate documentation (e.g. a documented deprecation) ` +
      `or a manipulation primitive aimed at the tool-selection pass.`,
    target,
    expected_observation:
      "The description contains phrasing engineered to make the AI prefer " +
      "this tool over alternatives.",
  };
}

export function stepCheckAlternatives(hit: J6Hit): VerificationStep {
  const target: Location = { kind: "tool", tool_name: hit.tool_name };
  return {
    step_type: "compare-baseline",
    instruction:
      "Enumerate alternative tools in the ecosystem that solve the same task. " +
      "Confirm whether this tool's preference claims are accurate or " +
      "unsupported.",
    target,
    expected_observation:
      "Alternatives exist and the preference claim is self-declared.",
  };
}
