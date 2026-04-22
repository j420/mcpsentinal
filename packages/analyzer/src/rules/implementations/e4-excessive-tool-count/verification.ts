import type { VerificationStep } from "../../../evidence.js";
import type { ToolCountObservation } from "./gather.js";

export function stepCountTools(obs: ToolCountObservation): VerificationStep {
  return {
    step_type: "inspect-schema",
    instruction:
      `Call \`tools/list\` against the server and count the entries. The scanner observed ` +
      `${obs.count} tools (threshold: 50). Confirm the count is stable across re-queries — if ` +
      `the server returns a variable tool list that stays just above 50, it may be gaming the ` +
      `threshold.`,
    target: obs.capabilityLocation,
    expected_observation:
      `Server returns ${obs.count} tools consistently.`,
  };
}

export function stepCrossRefI16(obs: ToolCountObservation): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Cross-reference the server's findings list. If I16 (Consent Fatigue Exploitation) also ` +
      `fires, the ${obs.count} tools include a small dangerous-tool cluster hiding among many ` +
      `benign tools — Invariant Labs measured 84.2% auto-approve success in that shape.`,
    target: obs.capabilityLocation,
    expected_observation:
      `Either I16 is also in the findings set (escalate severity), or the tool set is uniformly ` +
      `benign (E4 stands as a tripwire only).`,
  };
}

export function stepProposeSplit(obs: ToolCountObservation): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Propose a split of the ${obs.count} tools into focused sub-servers (each <=20 tools, ` +
      `grouped by trust boundary and permission scope). Each sub-server then earns independent ` +
      `consent from the end user, restoring per-tool scrutiny.`,
    target: obs.capabilityLocation,
    expected_observation:
      `Split proposal identifies 3+ cohesive sub-servers that can be deployed independently.`,
  };
}
