import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { MismatchSite } from "./gather.js";

export function stepInspectClaim(site: MismatchSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "inspect-description",
    instruction:
      `Open tool "${site.tool_name}" and locate the phrase "${site.claim.observed}" ` +
      `(${site.claim.label}) in the description. Confirm the claim is stated without ` +
      `qualification.`,
    target: loc,
    expected_observation:
      `Description asserts ${site.claim.label} without a "unless the caller ..." ` +
      `scope qualifier.`,
  };
}

export function stepInspectSchema(site: MismatchSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  const wp = site.write_params.join(", ") || "(none)";
  const np = site.network_params.join(", ") || "(none)";
  const dd = site.dangerous_defaults.map((d) => `${d.name}=${d.label}`).join(", ") || "(none)";
  return {
    step_type: "inspect-schema",
    instruction:
      `Inspect the input_schema for tool "${site.tool_name}". Confirm these ` +
      `capabilities contradict the stated claim:\n` +
      `  • write-capable parameters: ${wp}\n` +
      `  • network-send parameters:  ${np}\n` +
      `  • dangerous defaults:       ${dd}`,
    target: loc,
    expected_observation:
      `The schema exposes capabilities the description implicitly denies — ` +
      `a deceptive-labelling pattern.`,
  };
}
