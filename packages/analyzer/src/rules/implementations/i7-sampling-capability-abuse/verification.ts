import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { I7Fact } from "./gather.js";

export function stepInspectSamplingCapability(): VerificationStep {
  const target: Location = { kind: "capability", capability: "sampling" };
  return {
    step_type: "check-config",
    instruction:
      "Confirm the server's initialize response declares sampling: true. " +
      "Sampling lets the server invoke the AI client's model for inference; " +
      "when combined with any content-ingestion tool the server becomes a " +
      "23-41%-amplified injection channel per arXiv 2601.17549.",
    target,
    expected_observation:
      "declared_capabilities.sampling is true in the server's init response.",
  };
}

export function stepInspectIngestionTool(fact: I7Fact): VerificationStep {
  const first = fact.ingestion_nodes[0];
  const target: Location = { kind: "tool", tool_name: first.tool_name };
  return {
    step_type: "inspect-description",
    instruction:
      `Open tool "${first.tool_name}" and confirm it ingests content from an ` +
      `attacker-reachable source. The capability-graph classifier attributed ` +
      `"ingests-untrusted" at ${(first.confidence * 100).toFixed(0)}% ` +
      `confidence. Cross-reference G1 for the gateway-level finding.`,
    target,
    expected_observation:
      "The tool returns external content into the model context.",
  };
}

export function stepComparePairPrecedent(): VerificationStep {
  const target: Location = { kind: "capability", capability: "sampling" };
  return {
    step_type: "compare-baseline",
    instruction:
      "Reference arXiv 2601.17549 — empirical 23-41% attack amplification " +
      "when sampling is paired with ingestion. Verify whether a sampling " +
      "guardrail (per-call user confirmation, structural tagging of " +
      "ingested content) is implemented in this server.",
    target,
    expected_observation:
      "No guardrail distinguishes sampling requests that re-inject ingested " +
      "content from first-party model calls.",
  };
}
