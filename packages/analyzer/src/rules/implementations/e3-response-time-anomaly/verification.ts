import type { VerificationStep } from "../../../evidence.js";
import type { LatencyObservation } from "./gather.js";

export function stepRepeatMeasurement(obs: LatencyObservation): VerificationStep {
  return {
    step_type: "test-input",
    instruction:
      `Re-run \`initialize\` + \`tools/list\` against the MCP server from a network-adjacent client ` +
      `(same cloud region / same host) and record the response time. The scanner observed ` +
      `${obs.responseTimeMs}ms. Confirm the slowness is reproducible and not an artifact of ` +
      `scanner-side network path.`,
    target: obs.capabilityLocation,
    expected_observation:
      `Response time consistently exceeds 10,000ms from at least two network origins — ruling out ` +
      `transient single-path latency.`,
  };
}

export function stepCheckHostMetrics(obs: LatencyObservation): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Inspect the host CPU and event-loop metrics during the measurement window. Sustained CPU ` +
      `saturation while serving a tools/list is consistent with cryptojacking or runaway ` +
      `computation; low CPU with high latency suggests blocking I/O (external API calls, slow DB ` +
      `lookup, DNS issues).`,
    target: obs.capabilityLocation,
    expected_observation:
      `Host metrics explain the latency: either saturated CPU (escalate), blocked I/O (investigate ` +
      `downstream dependency), or network path issues (not a server-side problem).`,
  };
}

export function stepCrossRefToolCount(obs: LatencyObservation): VerificationStep {
  return {
    step_type: "inspect-schema",
    instruction:
      `Count the tools returned by tools/list. A server returning >100 tools with rich descriptions ` +
      `may legitimately take 10s+ to serialise. Cross-reference E4 (excessive tool count) — if ` +
      `E4 also fires, the slowness is more plausibly payload size than runtime abuse.`,
    target: obs.capabilityLocation,
    expected_observation:
      `Tool count is either small (<50, supporting the anomaly hypothesis) or large (supporting ` +
      `the payload-size hypothesis).`,
  };
}
