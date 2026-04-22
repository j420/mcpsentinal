import type { VerificationStep } from "../../../evidence.js";
import type { B7Site } from "./gather.js";
import { paramLocation } from "./gather.js";

export function stepInspectDefault(site: B7Site): VerificationStep {
  return {
    step_type: "inspect-schema",
    instruction:
      `Inspect the default value of parameter "${site.parameter_name}" in tool ` +
      `"${site.tool_name}". Confirm it is "${site.default_value}" and that this ` +
      `matches the dangerous pattern "${site.label}".`,
    target: paramLocation(site.tool_name, site.parameter_name),
    expected_observation:
      `default: "${site.default_value}" — ${site.rationale}.`,
  };
}

export function stepFlipSafeDefault(site: B7Site): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Change the default to the least-privilege value. Destructive booleans → ` +
      `false. read_only → true. Path parameters → a narrow, explicit default ` +
      `(e.g. the server's configured root, not "/").`,
    target: paramLocation(site.tool_name, site.parameter_name),
    expected_observation:
      `Default is the safe choice; callers who want the dangerous behaviour must ` +
      `opt in explicitly.`,
  };
}
