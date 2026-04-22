/**
 * B5 — Prompt Injection in Parameter Description (Rule Standard v2).
 *
 * Applies the A1 phrase catalogue (tokenised, noisy-OR aggregated) to
 * every parameter-level description field. Same linguistic technique
 * as A1 at a finer scope.
 */

import type { Severity } from "@mcp-sentinel/database";
import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import { gatherB5, paramLocation, type B5Site } from "./gather.js";
import { stepInspectParamDescription, stepRemoveDirective } from "./verification.js";
import { CONFIDENCE_CAP, CONFIDENCE_FLOOR } from "./data/config.js";

const RULE_ID = "B5";
const RULE_NAME = "Prompt Injection in Parameter Description";
const OWASP = "MCP01-prompt-injection";
const MITRE = "AML.T0054";

const REMEDIATION =
  "Rewrite every parameter description to contain ONLY factual type/format/unit " +
  "information. Remove imperative language, role prefixes, LLM control tokens, " +
  "authority claims, and references to prior approvals. Parameter descriptions " +
  "are a known secondary injection surface; LLMs consult them to choose argument " +
  "values.";

function severityFromConfidence(c: number): Severity {
  if (c >= 0.80) return "critical";
  if (c >= 0.60) return "high";
  return "medium";
}

class B5ParameterInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const sites = gatherB5(context);
    // Group by (tool, param) so each parameter gets one finding with all signals.
    const byKey = new Map<string, B5Site[]>();
    for (const s of sites) {
      const key = `${s.tool_name}::${s.parameter_name}`;
      const arr = byKey.get(key) ?? [];
      arr.push(s);
      byKey.set(key, arr);
    }
    const out: RuleResult[] = [];
    for (const hits of byKey.values()) {
      const finding = this.buildFinding(hits);
      if (finding) out.push(finding);
    }
    return out;
  }

  private buildFinding(hits: B5Site[]): RuleResult | null {
    const product = hits.reduce((p, h) => p * (1 - h.weight), 1);
    const aggregate = 1 - product;
    if (aggregate < CONFIDENCE_FLOOR) return null;
    const primary = hits.reduce((b, h) => (h.weight > b.weight ? h : b), hits[0]);
    const loc = paramLocation(primary.tool_name, primary.parameter_name);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: loc,
        observed: primary.observed,
        rationale:
          `Parameter "${primary.parameter_name}" of tool "${primary.tool_name}" has ` +
          `${hits.length} injection signal(s) in its description. LLMs read parameter ` +
          `descriptions to decide what value to place in the argument; directives ` +
          `here directly steer tool-call content.`,
      })
      .propagation({
        propagation_type: "description-directive",
        location: loc,
        observed:
          hits.map((h) => `"${h.label}" (weight ${h.weight.toFixed(2)})`).join(", "),
      })
      .sink({
        sink_type:
          primary.kind === "special-token" ? "code-evaluation" : "privilege-grant",
        location: loc,
        observed:
          `Combined noisy-OR confidence ${(aggregate * 100).toFixed(0)}% — directive ` +
          `reaches the LLM as parameter context on every tool invocation.`,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: aggregate >= 0.8 ? "trivial" : "moderate",
        scenario:
          `When the AI prepares to call "${primary.tool_name}", it reads the ` +
          `parameter description and follows any directive embedded there. Invariant ` +
          `Labs (2025) documents 84% tool-poisoning success through this surface.`,
      })
      .factor(
        "parameter_description_phrase_match",
        0.08,
        `${hits.length} injection signal(s) in parameter description.`,
      )
      .factor(
        "noisy_or_base_confidence",
        aggregate - 0.5,
        `Noisy-OR of ${hits.length} weights → ${(aggregate * 100).toFixed(0)}%.`,
      );

    builder.reference({
      id: "INVARIANT-LABS-MCP-INDIRECT-2025",
      title: "Invariant Labs (2025) — MCP Indirect Injection Research",
      url: "https://invariantlabs.ai/research/mcp-indirect-injection",
      relevance:
        "Parameter descriptions are a documented secondary injection surface; LLMs " +
        "consult them when filling argument values.",
    });

    builder.verification(stepInspectParamDescription(primary));
    builder.verification(stepRemoveDirective(primary));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "linguistic_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale: `B5 charter caps confidence at ${CONFIDENCE_CAP}.`,
      });
      chain.confidence = CONFIDENCE_CAP;
    }

    return {
      rule_id: RULE_ID,
      severity: severityFromConfidence(aggregate),
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new B5ParameterInjectionRule());

export { B5ParameterInjectionRule };
