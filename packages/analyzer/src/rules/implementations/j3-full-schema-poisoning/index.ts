/**
 * J3 — Full Schema Poisoning (Rule Standard v2).
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
import { gatherJ3, type J3Fact } from "./gather.js";
import { J3_CONFIDENCE_CAP } from "./data/config.js";
import { stepInspectSchema, stepCrossReferenceB5 } from "./verification.js";

const RULE_ID = "J3";
const RULE_NAME = "Full Schema Poisoning";
const OWASP = "MCP01-prompt-injection" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Sanitise ALL JSON Schema fields — not only description. Reject " +
  "injection phrasing in enum values, title, const, default, and examples. " +
  "Reference CyberArk's Full Schema Poisoning research (2025). Cross-check " +
  "B5 (parameter description injection) and B7 (dangerous defaults) for " +
  "adjacent findings.";

class FullSchemaPoisoningRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const { facts } = gatherJ3(context);
    return facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: J3Fact): RuleResult {
    const schemaLoc: Location = {
      kind: "schema",
      tool_name: fact.tool_name,
      json_pointer: "/",
    };
    const toolLoc: Location = { kind: "tool", tool_name: fact.tool_name };

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: schemaLoc,
        observed: fact.schema_preview,
        rationale:
          "Non-description schema fields (enum / title / const / default / " +
          "examples) are processed by LLMs as authoritative parameter " +
          "documentation. CyberArk's 2025 Full Schema Poisoning research " +
          "demonstrates equivalent effectiveness to description injection.",
      })
      .sink({
        sink_type: "code-evaluation",
        location: toolLoc,
        observed:
          `Catalogue hits: ${fact.hits.map((h) => h.key).join(", ")}. ` +
          `Aggregate weight: ${fact.aggregate_weight.toFixed(2)}.`,
      })
      .impact({
        impact_type: "session-hijack",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          "When the AI resolves tool parameters, it reads every schema field " +
          "— including non-description fields — as authoritative context. " +
          "Injection in enum / title / const / default fires the same LLM " +
          "behavioural path as a description-level injection, while bypassing " +
          "description-only scanners entirely.",
      })
      .factor(
        "schema_injection_matched",
        0.1,
        `Matched ${fact.hits.length} injection-phrase entries in non-` +
          `description schema fields. Noisy-OR aggregate ` +
          `${fact.aggregate_weight.toFixed(2)}.`,
      )
      .reference({
        id: "CyberArk-FSP-2025",
        title: "CyberArk Labs — Full Schema Poisoning (MCP)",
        url: "https://www.cyberark.com/resources/threat-research-blog/full-schema-poisoning-mcp",
        year: 2025,
        relevance:
          "Demonstrated that LLMs treat enum / title / const / default fields " +
          "as authoritative context, making non-description schema fields a " +
          "parallel injection surface.",
      })
      .verification(stepInspectSchema(fact))
      .verification(stepCrossReferenceB5(fact));

    const chain = capConfidence(builder.build(), J3_CONFIDENCE_CAP);
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
    rationale: `J3 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new FullSchemaPoisoningRule());

export { FullSchemaPoisoningRule };
