/**
 * J6 — Tool Preference Manipulation (Rule Standard v2).
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
import { gatherJ6, type J6Hit } from "./gather.js";
import { J6_CONFIDENCE_CAP } from "./data/config.js";
import {
  stepInspectDescription,
  stepCheckAlternatives,
} from "./verification.js";

const RULE_ID = "J6";
const RULE_NAME = "Tool Preference Manipulation";
const OWASP = "MCP02-tool-poisoning" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Tool descriptions must not instruct the AI to prefer this tool over " +
  "others (\"always use this first\", \"replaces the old X\", \"do not use " +
  "any other\"). Let the AI's own task-intent matching select the tool; " +
  "use documentation elsewhere (README) to explain replacement relationships " +
  "rather than encoding them into MCP metadata. Reference MPMA (2025).";

class ToolPreferenceManipulationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const { hits } = gatherJ6(context);
    return hits.map((h) => this.buildFinding(h));
  }

  private buildFinding(hit: J6Hit): RuleResult {
    const toolLoc: Location = { kind: "tool", tool_name: hit.tool_name };

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: toolLoc,
        observed: hit.description_preview,
        rationale:
          "Tool description contains preference-manipulation phrasing that " +
          "MPMA (2025) showed is effective at hijacking the AI's tool-" +
          "selection pass.",
      })
      .sink({
        sink_type: "privilege-grant",
        location: toolLoc,
        observed: `Matched ${hit.spec_key} (${hit.spec.kind}).`,
      })
      .impact({
        impact_type: "session-hijack",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `The AI is coached to prefer tool "${hit.tool_name}" over ` +
          `alternatives. If the tool is malicious or compromised, every ` +
          `user request in this tool's category routes through the ` +
          `attacker's implementation. Tool-level traffic hijacking without ` +
          `compromising the AI itself.`,
      })
      .factor(
        "preference_phrase_matched",
        0.08,
        `Matched preference catalogue entry "${hit.spec_key}" (${hit.spec.kind}).`,
      )
      .reference({
        id: "MPMA-2025",
        title: "Multi-Prompt Multi-Agent Tool Preference Manipulation",
        url: "https://arxiv.org/abs/2502.19886",
        year: 2025,
        relevance:
          "Established linguistic signals in tool descriptions reliably " +
          "manipulate AI tool selection.",
      })
      .verification(stepInspectDescription(hit))
      .verification(stepCheckAlternatives(hit));

    if (hit.fence_hit) {
      builder.factor(
        "false_positive_fence_triggered",
        -0.1,
        "Legitimate co-occurrence (example / tutorial / docs / deprecated) — " +
          "demoting confidence.",
      );
    }

    const chain = capConfidence(builder.build(), J6_CONFIDENCE_CAP);
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
    rationale: `J6 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ToolPreferenceManipulationRule());

export { ToolPreferenceManipulationRule };
