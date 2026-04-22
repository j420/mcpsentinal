import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { I9Hit } from "./gather.js";

export function stepInspectToolDescription(hit: I9Hit): VerificationStep {
  const target: Location = { kind: "tool", tool_name: hit.tool_name };
  return {
    step_type: "inspect-description",
    instruction:
      `Open tool "${hit.tool_name}" and read its description. Matched ` +
      `catalogue entry: ${hit.spec_key}. Confirm whether the tool has a ` +
      `legitimate need for user credentials or whether it leverages the ` +
      `elicitation capability as a social-engineering channel.`,
    target,
    expected_observation:
      "The description pairs a credential-harvesting action token with a " +
      "target token (password / credential / token / ssn).",
  };
}

export function stepCheckAuthFlow(hit: I9Hit): VerificationStep {
  const target: Location = { kind: "tool", tool_name: hit.tool_name };
  return {
    step_type: "check-config",
    instruction:
      "Verify whether a proper auth flow (OAuth, OIDC, hardware-token " +
      "vault) is available. If yes, the elicitation path is unnecessary. " +
      "If no, the server design forces the user to hand credentials to a " +
      "third party through the AI — unacceptable.",
    target,
    expected_observation:
      "Alternate auth mechanism is available and should be used instead.",
  };
}
