/**
 * Confidence policy for LLM-derived compliance findings.
 *
 * Per ADR-009: any finding whose verdict came from an LLM is capped at
 * 0.85 confidence. Deterministic findings (where the rule's
 * gather phase already detected the violation and the LLM merely
 * narrates it) keep the chain's natural confidence.
 *
 * The cap is applied as a confidence factor on the EvidenceChain so the
 * audit trail records WHY the cap was applied.
 */

import { EvidenceChainBuilder, type EvidenceChain } from "@mcp-sentinel/analyzer";
import type { JudgedTestResult } from "../types.js";

export const LLM_CONFIDENCE_CAP = 0.85;

/**
 * Apply the LLM cap to a chain by adding a negative confidence factor.
 * The chain's confidence is recomputed via the builder so the cap appears
 * in the audit trail.
 */
export function applyLLMCap(chain: EvidenceChain, judged: JudgedTestResult): EvidenceChain {
  if (chain.confidence <= LLM_CONFIDENCE_CAP) {
    return chain;
  }
  // Reduction = how much over the cap we are.
  const reduction = -(chain.confidence - LLM_CONFIDENCE_CAP);
  return {
    ...chain,
    confidence: LLM_CONFIDENCE_CAP,
    confidence_factors: [
      ...chain.confidence_factors,
      {
        factor: "llm-reasoning-cap",
        adjustment: reduction,
        rationale: `LLM-derived verdict (${judged.verdict}) capped at 0.85 per ADR-009. Judge confirmation: ${judged.judge_confirmed}.`,
      },
    ],
  };
}

/**
 * Helper for rules that want to start a chain pre-tagged as LLM-derived.
 */
export function newLLMBackedChain(): EvidenceChainBuilder {
  return new EvidenceChainBuilder().factor(
    "analysis-technique",
    0,
    "Finding produced via LLM-mediated adversarial test (compliance-agents package, ADR-009 exception).",
  );
}
