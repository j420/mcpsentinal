import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { CountSite } from "./gather.js";
import { PARAM_COUNT_THRESHOLD } from "./data/thresholds.js";

export function stepInspectCount(site: CountSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "inspect-schema",
    instruction:
      `Count the top-level properties in tool "${site.tool_name}"'s input_schema. ` +
      `Confirm the count is ${site.count}.`,
    target: loc,
    expected_observation: `${site.count} top-level parameters (threshold ${PARAM_COUNT_THRESHOLD}).`,
  };
}

export function stepProposeGrouping(site: CountSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "compare-baseline",
    instruction:
      `Group related parameters into nested objects. Example: convert the ${site.count} ` +
      `flat parameters into 3-5 named groups (e.g. 'source', 'target', 'options'). ` +
      `This preserves functionality while reducing the surface reviewers must inspect.`,
    target: loc,
    expected_observation:
      `A refactored schema with ${PARAM_COUNT_THRESHOLD} or fewer top-level groups, ` +
      `each focused on a single concern.`,
  };
}
