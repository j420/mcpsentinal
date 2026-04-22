import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { ClaimSite } from "./gather.js";

export function stepInspectClaim(site: ClaimSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "inspect-description",
    instruction:
      `Open tool "${site.tool_name}" and read its description. Locate the phrase ` +
      `"${site.observed}" at offset ${site.offset}. Confirm the claim is made without ` +
      `a qualifying scope ("... within the configured root directory").`,
    target: loc,
    expected_observation:
      `Description advertises ${site.label} at offset ${site.offset} without a ` +
      `scope-narrowing qualifier.`,
  };
}

export function stepInspectSchema(tool_name: string, hasConstraints: boolean): VerificationStep {
  const loc: Location = { kind: "tool", tool_name };
  return {
    step_type: "inspect-schema",
    instruction:
      `Inspect the input_schema for tool "${tool_name}". Compare the structured ` +
      `constraints (enum, pattern, maxLength, min/max) against the description's ` +
      `scope claim. A narrow schema alongside a broad claim is a deceptive-labelling ` +
      `pattern.`,
    target: loc,
    expected_observation: hasConstraints
      ? `Schema has structured constraints; the broad description overclaims the true scope.`
      : `Schema has no constraints that contradict the description — the claim is ` +
        `consistent with unlimited runtime scope.`,
  };
}
