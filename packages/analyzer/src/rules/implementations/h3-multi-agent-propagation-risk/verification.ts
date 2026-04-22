/**
 * H3 verification-step builders. Auditors open the tools/list response
 * and confirm the propagation-sink classification.
 *
 * No regex, no long string-literal arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { H3Site } from "./gather.js";

export function stepInspectSink(site: H3Site): VerificationStep {
  const target = site.parameterLocation ?? site.toolLocation;
  return {
    step_type: "inspect-description",
    instruction:
      `Review the tool "${site.toolName}". The scanner classified it as a ` +
      `${site.sinkKind} surface because ${site.observed}. ` +
      site.entry.rationale,
    target,
    expected_observation:
      `The tool metadata contains "${site.matchedToken}" and the tool does not ` +
      `declare a trust-boundary / sanitization signal in its description.`,
  };
}

export function stepCheckSanitization(site: H3Site): VerificationStep {
  return {
    step_type: "inspect-description",
    instruction:
      `Check the tool's description for a sanitization signal — phrases like ` +
      `"validates upstream", "sanitises", "trust boundary", "untrusted ` +
      `content". When such a phrase is present, the finding should be ` +
      `suppressed. The scanner found ${site.sanitizationDeclared ? "a" : "no"} ` +
      `sanitization signal in the description today.`,
    target: site.toolLocation,
    expected_observation: site.sanitizationDeclared
      ? `A sanitization signal was seen — re-check whether the finding should be dismissed.`
      : `No sanitization signal was seen — the trust-boundary declaration gap is confirmed.`,
  };
}

export function stepReviewPropagationDoc(site: H3Site): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Cross-reference the tool against the multi-agent architecture it ` +
      `participates in (LangGraph, AutoGen, CrewAI, or a Claude multi-agent ` +
      `pattern). Confirm whether another agent's output flows into this ` +
      `tool's parameters (${site.sinkKind === "agent-input" ? "this is the " +
      "primary concern" : "this amplifies the shared-memory-writer finding"}).`,
    target: site.capabilityLocation,
    expected_observation:
      `The tool is used as an inter-agent hand-off surface without a declared ` +
      `trust boundary.`,
  };
}
