import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { I12UndeclaredFact } from "./gather.js";

export function stepInspectHandlers(fact: I12UndeclaredFact): VerificationStep {
  const target: Location = {
    kind: "capability",
    capability: fact.capability === "elicitation" ? "tools" : fact.capability,
  };
  return {
    step_type: "inspect-source",
    instruction:
      `Search the server source for handler registrations matching the ` +
      `${fact.capability} capability vocabulary: ` +
      `${fact.matched_tokens.join(", ")}. Compare with the initialize ` +
      `response capabilities object to confirm ${fact.capability} was not ` +
      `declared.`,
    target,
    expected_observation:
      `Source contains ${fact.capability} handlers but declared_capabilities.` +
      `${fact.capability} is missing or false.`,
  };
}

export function stepCheckInitializeResponse(
  fact: I12UndeclaredFact,
): VerificationStep {
  const target: Location = {
    kind: "capability",
    capability: fact.capability === "elicitation" ? "tools" : fact.capability,
  };
  return {
    step_type: "check-config",
    instruction:
      "Compare the server's initialize response against the observed " +
      "handler surface. Every capability USED must be DECLARED, not only " +
      "a subset.",
    target,
    expected_observation:
      `The initialize response does not declare ${fact.capability}.`,
  };
}
