import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { J5Hit } from "./gather.js";

export function stepInspectResponseConstruction(
  hit: J5Hit,
): VerificationStep {
  const target: Location = {
    kind: "source",
    file: "<server source>",
    line: hit.line_number,
  };
  return {
    step_type: "inspect-source",
    instruction:
      `At line ${hit.line_number}, inspect the response / error construction. ` +
      `Matched pattern kind: ${hit.spec.kind}. Determine whether the ` +
      `response string carries a behavioural directive intended for the AI ` +
      `client.`,
    target,
    expected_observation: hit.line_preview,
  };
}

export function stepTestRuntime(): VerificationStep {
  const target: Location = {
    kind: "source",
    file: "<server source>",
    line: 1,
  };
  return {
    step_type: "test-input",
    instruction:
      "Trigger the error / response path in a dynamic-tester sandbox (with " +
      "consent, per packages/dynamic-tester) and observe the raw response. " +
      "Confirm the manipulation string reaches the client verbatim.",
    target,
    expected_observation:
      "Runtime response contains the static manipulation instruction.",
  };
}
