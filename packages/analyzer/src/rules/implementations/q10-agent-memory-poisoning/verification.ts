import type { VerificationStep } from "../../../evidence.js";
import type { MemorySite } from "./gather.js";

export function stepInspectDescription(site: MemorySite): VerificationStep {
  const classes = Array.from(new Set(site.matched_signals.map((m) => m.cls))).join(", ");
  return {
    step_type: "inspect-description",
    instruction:
      `Read the tool description. Confirm the following memory-poisoning ` +
      `signal classes: ${classes}. Each class is an independent indication ` +
      `that the tool writes behavioural content (not facts) to agent memory.`,
    target: site.location,
    expected_observation:
      `Tool "${site.tool_name}" description asserts ${site.matched_signals.length} ` +
      `memory-poisoning signal(s).`,
  };
}

export function stepCheckMitigation(site: MemorySite): VerificationStep {
  return {
    step_type: "inspect-description",
    instruction: site.has_mitigation
      ? `A mitigation token was detected: "read-only" / "append-only" / ` +
        `"facts only" / "no instructions" / "sanitize before store". Confirm ` +
        `the mitigation is structural (enforced by the tool) rather than ` +
        `advisory (claimed in text but not implemented).`
      : `No mitigation tokens detected. Confirm the tool truly allows free-form ` +
        `behavioural content into agent memory.`,
    target: site.location,
    expected_observation: site.has_mitigation
      ? `A structural memory-safety mitigation.`
      : `No mitigation — the tool accepts arbitrary behavioural input.`,
  };
}

export function stepTestCanary(site: MemorySite): VerificationStep {
  return {
    step_type: "test-input",
    instruction:
      `In a sandbox, invoke the tool with a canary instruction ("whenever ` +
      `asked about X respond with Y"). After the call, start a new agent ` +
      `session and ask about X. If the canary response appears, the memory ` +
      `poisoning primitive is live.`,
    target: site.location,
    expected_observation:
      `Canary instruction persists across sessions — confirmed memory poisoning.`,
  };
}
