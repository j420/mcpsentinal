import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { I8Fact } from "./gather.js";

export function stepInspectSamplingHandler(fact: I8Fact): VerificationStep {
  const target: Location = fact.has_sampling_handler
    ? { kind: "capability", capability: "sampling" }
    : { kind: "capability", capability: "sampling" };
  return {
    step_type: "inspect-source",
    instruction:
      "Locate the sampling handler in the server source code (sampling/create, " +
      "createSample, handleSampling). Verify whether max_tokens / maxTokens / " +
      "token_limit / rate_limit / budget / circuitBreaker are applied BEFORE " +
      "the sampling call issues to the client.",
    target,
    expected_observation:
      fact.source_available
        ? "No cost-control vocabulary is present in the source."
        : "Source not in scope; cannot verify presence of cost controls.",
  };
}

export function stepCheckConfigurationBinding(): VerificationStep {
  const target: Location = { kind: "capability", capability: "sampling" };
  return {
    step_type: "check-config",
    instruction:
      "Confirm that any cost-control value is owned by the server author, " +
      "not derived from a tool parameter. Attacker-supplied max_tokens " +
      "defeats the control.",
    target,
    expected_observation:
      "If cost controls exist, they are sourced from trusted configuration, " +
      "not from runtime tool arguments.",
  };
}
