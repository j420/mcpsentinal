import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { UnconstrainedSite } from "./gather.js";

export function stepInspectSchema(site: UnconstrainedSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  const list = site.unconstrained.map((u) => `${u.param} (${u.type})`).join(", ");
  return {
    step_type: "inspect-schema",
    instruction:
      `Open the input_schema for tool "${site.tool_name}". Confirm the following ` +
      `parameters lack structural validation constraints:\n  ${list}`,
    target: loc,
    expected_observation:
      `${site.unconstrained.length} of ${site.total_params} parameters lack constraints ` +
      `(string: maxLength/enum/pattern/format; number: min/max).`,
  };
}

export function stepAddConstraint(site: UnconstrainedSite): VerificationStep {
  const first = site.unconstrained[0];
  const loc: Location = {
    kind: "parameter",
    tool_name: site.tool_name,
    parameter_path: `input_schema.properties.${first.param}`,
  };
  return {
    step_type: "check-config",
    instruction:
      `For each unconstrained parameter, add at least one validation keyword. ` +
      `Example: ${first.param} (${first.type}) → add ${first.type === "string" ? "maxLength or pattern" : "minimum and maximum"}.`,
    target: loc,
    expected_observation:
      `Every parameter in the schema declares at least one structural constraint.`,
  };
}
