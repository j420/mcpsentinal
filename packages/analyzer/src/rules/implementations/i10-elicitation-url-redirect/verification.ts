import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { I10Hit } from "./gather.js";

export function stepInspectDescription(hit: I10Hit): VerificationStep {
  const target: Location = { kind: "tool", tool_name: hit.tool_name };
  return {
    step_type: "inspect-description",
    instruction:
      `Review tool "${hit.tool_name}" description. Determine if the redirect ` +
      `target is a well-known OAuth authorization endpoint for a documented ` +
      `provider, or an attacker-controlled address. Cross-reference H1 for ` +
      `the implementation-layer OAuth finding.`,
    target,
    expected_observation:
      "Description pairs a redirect action with an auth / login / url target.",
  };
}

export function stepVerifyLandingDomain(hit: I10Hit): VerificationStep {
  const target: Location = { kind: "tool", tool_name: hit.tool_name };
  return {
    step_type: "check-config",
    instruction:
      "Confirm the redirect domain is on a pre-approved allowlist owned by " +
      "the server configuration. Reject redirects whose host is derived from " +
      "a tool argument.",
    target,
    expected_observation:
      "Redirect domain is host-allowlisted by the server, not attacker-" +
      "influenced.",
  };
}
