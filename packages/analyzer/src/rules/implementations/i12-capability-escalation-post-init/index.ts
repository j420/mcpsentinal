/**
 * I12 — Capability Escalation Post-Init (Rule Standard v2).
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
import { gatherI12, type I12UndeclaredFact } from "./gather.js";
import { I12_CONFIDENCE_CAP } from "./data/config.js";
import {
  stepCheckInitializeResponse,
  stepInspectHandlers,
} from "./verification.js";

const RULE_ID = "I12";
const RULE_NAME = "Capability Escalation Post-Init";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Declare EVERY capability the server uses in the initialize response. " +
  "Clients scope their consent and their risk model to the declared " +
  "capabilities; undeclared capabilities bypass the client's capability " +
  "gate. If a capability is exposed by the code, it must appear in " +
  "initialize → capabilities.";

class CapabilityEscalationPostInitRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = {
    source_code: true,
    declared_capabilities: true,
  };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const { facts } = gatherI12(context);
    return facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: I12UndeclaredFact): RuleResult {
    const loc: Location = {
      kind: "capability",
      capability: fact.capability === "elicitation" ? "tools" : fact.capability,
    };

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: loc,
        observed: `Handlers observed: ${fact.matched_tokens.join(", ")}`,
        rationale:
          `Server source contains the ${fact.capability} capability's handler ` +
          `vocabulary (${fact.spec.purpose}) but the initialize response does ` +
          `not declare it. This is a confused-deputy attack on the ` +
          `capability-negotiation protocol.`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: loc,
        observed:
          "Capability negotiation is bypassed — the client scoped its consent " +
          "to declared capabilities only.",
      })
      .sink({
        sink_type: "privilege-grant",
        location: loc,
        observed:
          `${fact.capability} capability is used without a client-side ` +
          `capability gate.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `The server executes ${fact.capability} operations without ` +
          `announcing the capability at init. Clients that scope their ` +
          `security model by declared capabilities are bypassed entirely — ` +
          `every downstream I-rule check assumed the capability was ` +
          `properly negotiated.`,
      })
      .factor(
        "undeclared_capability",
        0.1,
        `${fact.capability} handlers present in source but not declared in ` +
          `capabilities.`,
      )
      .verification(stepInspectHandlers(fact))
      .verification(stepCheckInitializeResponse(fact));

    const chain = capConfidence(builder.build(), I12_CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
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
    rationale: `I12 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new CapabilityEscalationPostInitRule());

export { CapabilityEscalationPostInitRule };
