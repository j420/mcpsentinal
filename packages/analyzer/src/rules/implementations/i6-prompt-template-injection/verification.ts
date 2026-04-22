import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { I6Fact } from "./gather.js";

export function stepInspectPrompt(fact: I6Fact): VerificationStep {
  const target: Location = {
    kind: "prompt",
    name: fact.prompt_name,
    field: "description",
  };
  const hitDescriptor = fact.hits
    .map((h) => `${h.matched_field}:${h.key}`)
    .join(", ");
  return {
    step_type: "inspect-description",
    instruction:
      `Open the prompt template "${fact.prompt_name}" and inspect the ` +
      `name, description, and argument descriptions. The gather step matched ` +
      `${hitDescriptor}. Confirm whether the phrasing is legitimate template ` +
      `instruction or a behavioural directive aimed at the AI client.`,
    target,
    expected_observation:
      "Template metadata contains role-override, delimiter, or action " +
      "directive tokens matching the shared INJECTION_PHRASES catalogue.",
  };
}

export function stepCheckReuseAmplification(fact: I6Fact): VerificationStep {
  const target: Location = {
    kind: "prompt",
    name: fact.prompt_name,
  };
  return {
    step_type: "compare-baseline",
    instruction:
      "Check the server's published usage of this prompt template. Prompt " +
      "templates are designed to be invoked repeatedly; a poisoned prompt " +
      "scales with usage. Confirm whether this prompt is invoked by other " +
      "integrations or only by a narrow internal consumer.",
    target,
    expected_observation:
      "The prompt's reuse frequency amplifies the impact of any injection.",
  };
}
