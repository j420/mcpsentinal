/** M7 — Multi-Turn State Injection (v2). AST only; zero regex; cap 0.85. */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherM7, type InjectionSite } from "./gather.js";
import {
  stepInspectMutation,
  stepCheckRead,
  stepCheckBoundary,
} from "./verification.js";

const RULE_ID = "M7";
const OWASP = "MCP01-prompt-injection" as const;
const MITRE = "AML.T0058" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Tool code must not mutate conversation history, chat turns, or shared " +
  "agent context. If the tool needs to persist information across turns, " +
  "return it as tool output and let the AI client decide whether to retain " +
  "it. If a dedicated memory capability is intended, declare it via the " +
  "MCP memory extension and confine writes to a bounded namespace.";

const REF_MITRE_T0058 = {
  id: "MITRE-AML-T0058",
  title: "MITRE ATLAS AML.T0058 — AI Agent Context Poisoning",
  url: "https://atlas.mitre.org/techniques/AML.T0058",
  relevance:
    "Writes to conversation state enable persistent context poisoning. A " +
    "single poisoned write affects every subsequent agent turn.",
} as const;

class M7Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = "Multi-Turn State Injection";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const sites = gatherM7(context);
    return sites.map((s) => this.buildFinding(s));
  }

  private buildFinding(site: InjectionSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `Tool code at this line performs a ${site.kind} on the ` +
          `conversation-state expression "${site.target_expr}" using ` +
          `method "${site.method}". Tools should treat the agent's ` +
          `conversation history as read-only.`,
      })
      .sink({
        sink_type: "config-modification",
        location: site.location,
        observed: `Conversation state write: ${site.target_expr}.${site.method}(...)`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `Tool modifies conversation state. Injected or mutated messages ` +
          `persist across turns and poison the AI's context — enabling ` +
          `persistent prompt injection, role confusion, and safety-instruction ` +
          `displacement.`,
      })
      .factor(
        "state_mutation",
        site.kind === "direct-assignment" ? 0.14 : 0.12,
        `${site.kind} on conversation-state expression "${site.target_expr}"`,
      );

    builder.reference(REF_MITRE_T0058);
    builder.verification(stepInspectMutation(site));
    builder.verification(stepCheckRead(site));
    builder.verification(stepCheckBoundary(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity: "high",
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
    rationale: `M7 cap ${cap}: AST cannot prove the mutation is visible to subsequent turns.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new M7Rule());
export { M7Rule };
