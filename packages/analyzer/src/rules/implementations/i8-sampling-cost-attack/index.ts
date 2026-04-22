/**
 * I8 — Sampling Cost Attack (Rule Standard v2).
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import type { Location } from "../../location.js";
import { gatherI8, type I8Fact } from "./gather.js";
import { I8_CONFIDENCE_CAP } from "./data/config.js";
import {
  stepInspectSamplingHandler,
  stepCheckConfigurationBinding,
} from "./verification.js";

const RULE_ID = "I8";
const RULE_NAME = "Sampling Cost Attack";
const OWASP = "MCP07-insecure-config" as const;

const REMEDIATION =
  "Apply server-side cost controls to every sampling request. Require at " +
  "minimum: (a) max_tokens cap owned by the server configuration (not by " +
  "a tool argument), (b) a rate limit on sampling frequency per client / " +
  "per tool / per time window, (c) a circuit-breaker that halts sampling " +
  "when an error rate threshold is crossed. Never bind sampling max_tokens " +
  "to tool-argument values.";

class SamplingCostAttackRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { declared_capabilities: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherI8(context);
    if (!gathered.fact) return [];
    return [this.buildFinding(gathered.fact)];
  }

  private buildFinding(fact: I8Fact): RuleResult {
    const loc: Location = { kind: "capability", capability: "sampling" };
    const severity: "high" | "informational" = fact.source_available
      ? "high"
      : "informational";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "environment",
        location: loc,
        observed: "declared_capabilities.sampling === true",
        rationale:
          "Server declares it can call back into the client's model for " +
          "inference. Each sampling request is a paid AI call on the client.",
      })
      .sink({
        sink_type: "network-send",
        location: loc,
        observed:
          "Sampling requests → client model inference API → billable calls",
      })
      .mitigation({
        mitigation_type: "rate-limit",
        present: false,
        location: loc,
        detail: fact.source_available
          ? "No cost-control vocabulary (max_tokens, rateLimit, cost_limit, " +
            "budget, circuitBreaker) observed in source."
          : "Source code not in scope — cannot verify presence of cost controls.",
      })
      .impact({
        impact_type: "denial-of-service",
        scope: "user-data",
        exploitability: "trivial",
        scenario:
          "A server can issue rapid sampling requests, each triggering a " +
          "paid model call on the client. Without token limits or rate " +
          "limiting, a single server can exhaust the client operator's " +
          "inference budget. This is financial DoS: the service remains " +
          "available but becomes prohibitively expensive.",
      })
      .factor("sampling_declared", 0.08, "Sampling capability declared at init.")
      .factor(
        "cost_control_absent",
        fact.source_available ? 0.08 : 0.0,
        fact.source_available
          ? "Exhaustive scan of source-code cost-control vocabulary returned 0 hits."
          : "Source not available — negative-signal inference not verified.",
      )
      .verification(stepInspectSamplingHandler(fact))
      .verification(stepCheckConfigurationBinding());

    const chain = capConfidence(builder.build(), I8_CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: null,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale: `I8 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new SamplingCostAttackRule());

export { SamplingCostAttackRule };
